#!/usr/bin/env python3
"""Monitor top processes by open file count and notify when one exceeds a threshold."""

import argparse
import ctypes
import ctypes.util
import errno
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter


def count_open_files() -> tuple[
    Counter,
    dict[int, str],
    dict[int, Counter],
    dict[int, list[tuple[str, str, str]]],
]:
    """Scan all open FDs once, returning counts/names/histograms/details per PID.

    Capturing per-FD detail in this same pass (rather than re-running `lsof -p <pid>`
    after a breach is detected) avoids racing short-lived processes that exit before
    the follow-up query can read their FD table.
    """
    # -n: no DNS resolution. -P: numeric ports. -w: suppress warnings.
    # -F pcftn: machine-readable, one tag per line — p (pid), c (command),
    # f (fd num), t (type), n (name). Each FD appears as f→t→n.
    result = subprocess.run(
        ["lsof", "-n", "-P", "-w", "-F", "pcftn"],
        capture_output=True,
        text=True,
        check=False,
    )

    counts: Counter = Counter()
    names: dict[int, str] = {}
    histograms: dict[int, Counter] = {}
    details: dict[int, list[tuple[str, str, str]]] = {}

    current_pid: int | None = None
    current_fd: str | None = None
    current_type: str | None = None

    for line in result.stdout.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            try:
                current_pid = int(value)
            except ValueError:
                current_pid = None
            current_fd = None
            current_type = None
        elif tag == "c" and current_pid is not None:
            names[current_pid] = value
        elif tag == "f" and current_pid is not None:
            current_fd = value
            current_type = None
        elif tag == "t" and current_pid is not None:
            current_type = value
        elif tag == "n" and current_pid is not None:
            counts[current_pid] += 1
            fd_type = current_type or "?"
            histograms.setdefault(current_pid, Counter())[fd_type] += 1
            details.setdefault(current_pid, []).append(
                (current_fd or "?", fd_type, value)
            )
            current_fd = None
            current_type = None

    return counts, names, histograms, details


_LIBC: ctypes.CDLL | None = None


def _libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _LIBC


def sysctl_int(name: str) -> int | None:
    """Read an integer sysctl via libc.sysctlbyname.

    Used instead of `subprocess.run(["sysctl", ...])` so the system-FD probe
    keeps working even when the kernel file table is exhausted (ENFILE) and
    fork/exec is failing — exactly the condition this watcher needs to react to.
    """
    val = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(val))
    rc = _libc().sysctlbyname(
        name.encode(), ctypes.byref(val), ctypes.byref(size), None, 0
    )
    if rc != 0:
        return None
    return val.value


def system_fd_pressure() -> tuple[int, int] | None:
    """Return (kern.num_files, kern.maxfiles), or None if either lookup fails."""
    num = sysctl_int("kern.num_files")
    cap = sysctl_int("kern.maxfiles")
    if num is None or cap is None or cap <= 0:
        return None
    return num, cap


def kill_pid(pid: int, sigterm_timeout: float = 3.0) -> str:
    """SIGTERM, poll for up to `sigterm_timeout`, then SIGKILL if still alive.

    Returns one of: 'TERM' (exited on SIGTERM), 'KILL' (escalated to SIGKILL),
    'GONE' (already dead before signal), or 'DENIED' (no permission).
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "GONE"
    except PermissionError:
        return "DENIED"

    deadline = time.monotonic() + sigterm_timeout
    while time.monotonic() < deadline:
        time.sleep(0.1)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "TERM"

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "TERM"
    return "KILL"


def _run_alerter_and_handle_click(cmd: list[str], reveal_path: str | None) -> None:
    """Run alerter (blocks until user interacts); reveal `reveal_path` in Finder on body click."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return
    if reveal_path and result.stdout.strip() == "@CONTENTCLICKED":
        subprocess.run(["open", "-R", reveal_path], check=False)


def notify(title: str, message: str, reveal_path: str | None = None) -> None:
    """Display a native macOS notification.

    Prefers `alerter` (Apple Silicon native, actively maintained). When
    `reveal_path` is given, clicking the banner body opens Finder with that
    path revealed. Falls back to osascript when alerter isn't installed.
    """
    alerter = shutil.which("alerter")
    if alerter:
        # alerter blocks until the user clicks / dismisses / times out, so
        # run it in a daemon thread to keep the polling loop alive. --sender
        # spoofs Terminal's icon for nicer attribution, but click events still
        # reach alerter's NSUserNotificationCenterDelegate while alerter is
        # alive (vjeantet/alerter NotificationManager.swift userNotificationCenter:didActivate:),
        # so the @CONTENTCLICKED handoff still works.
        cmd = [alerter, "--title", title, "--message", message, "--sender", "com.apple.Terminal"]
        threading.Thread(
            target=_run_alerter_and_handle_click,
            args=(cmd, reveal_path),
            daemon=True,
        ).start()
        return

    safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
    safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{safe_message}" with title "{safe_title}"'
    subprocess.run(["osascript", "-e", script], check=False)


DEFAULT_LOG = os.path.expanduser("~/Library/Logs/files-watcher.log")
DEFAULT_PIDFILE = os.path.expanduser("~/Library/Logs/files-watcher.pid")
DEFAULT_SNAPSHOT_DIR = os.path.expanduser("~/Library/Logs/files-watcher-snapshots")
LAUNCHD_LABEL = "local.files-watcher"
LAUNCHD_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist")


def snapshot_process(
    pid: int,
    name: str,
    count: int,
    threshold: int,
    histogram: Counter,
    fds: list[tuple[str, str, str]],
    snapshot_dir: str,
) -> str | None:
    """Write a snapshot of the offending PID's FDs from data captured at detection time.

    Returns the path written, or None if snapshotting was disabled.
    """
    if not snapshot_dir:
        return None

    os.makedirs(snapshot_dir, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H-%M-%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "unknown"
    path = os.path.join(snapshot_dir, f"{ts}-{safe_name}-{pid}.txt")

    with open(path, "w") as f:
        f.write(f"# files-watcher snapshot\n")
        f.write(f"# captured: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n")
        f.write(f"# pid: {pid}\n")
        f.write(f"# command: {name}\n")
        f.write(f"# open files at detection: {count}\n")
        f.write(f"# threshold: {threshold}\n")
        f.write(f"# fds captured: {len(fds)}\n")
        f.write("\n## FD type histogram\n")
        for fd_type, n in histogram.most_common():
            f.write(f"{n:>8}  {fd_type}\n")
        f.write("\n## FD detail (fd, type, name)\n")
        for fd, fd_type, fd_name in fds:
            f.write(f"{fd:>6}  {fd_type:<10}  {fd_name}\n")

    return path


def daemonize(log_file: str, pidfile: str) -> None:
    """Detach from the controlling terminal via the standard double-fork dance."""
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    if os.path.exists(pidfile):
        try:
            with open(pidfile) as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            print(
                f"watcher already running (PID {old_pid}); kill it first or remove {pidfile}",
                file=sys.stderr,
            )
            sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            pass  # stale pidfile

    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    os.chdir("/")
    os.umask(0o022)

    sys.stdout.flush()
    sys.stderr.flush()
    log_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log_fd, sys.stdout.fileno())
    os.dup2(log_fd, sys.stderr.fileno())
    os.close(log_fd)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, sys.stdin.fileno())
    os.close(devnull)

    with open(pidfile, "w") as f:
        f.write(str(os.getpid()))


def stop_daemon(pidfile: str) -> int:
    """Send SIGTERM to the PID in pidfile, escalate to SIGKILL if needed."""
    try:
        with open(pidfile) as f:
            pid = int(f.read().strip())
    except FileNotFoundError:
        print(f"no pidfile at {pidfile}; nothing to stop", file=sys.stderr)
        return 1
    except ValueError:
        print(f"pidfile {pidfile} is malformed", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"PID {pid} not running; removing stale pidfile")
        os.unlink(pidfile)
        return 0
    except PermissionError:
        print(f"no permission to signal PID {pid}", file=sys.stderr)
        return 1

    for _ in range(20):  # up to ~2s
        time.sleep(0.1)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
    else:
        os.kill(pid, signal.SIGKILL)

    try:
        os.unlink(pidfile)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    print(f"stopped PID {pid}")
    return 0


def _passthrough_args(argv: list[str]) -> list[str]:
    """Strip lifecycle flags so the remaining argv can be re-embedded under launchd."""
    drop_bare = {"--daemon", "--stop", "--install-launchd", "--uninstall-launchd"}
    drop_with_value = {"--log-file", "--pidfile"}  # launchd manages logs separately
    out: list[str] = []
    skip_next = False
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a in drop_bare:
            continue
        if a in drop_with_value:
            skip_next = True
            continue
        if any(a.startswith(p + "=") for p in drop_with_value):
            continue
        out.append(a)
    return out


def install_launchd(script_path: str, log_file: str, extra_args: list[str]) -> int:
    """Write and load a launchd plist that runs the watcher at login."""
    if os.path.exists(LAUNCHD_PLIST):
        print(f"launchd plist already exists at {LAUNCHD_PLIST}; uninstall first", file=sys.stderr)
        return 1

    python_bin = shutil.which("python3") or sys.executable
    program_args = [python_bin, script_path, *extra_args]

    def xml_escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    args_xml = "\n".join(f"    <string>{xml_escape(a)}</string>" for a in program_args)

    # Include rbenv shims so terminal-notifier resolves under launchd's minimal PATH.
    env_path = ":".join([
        os.path.expanduser("~/.rbenv/shims"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ])

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{xml_escape(log_file)}</string>
  <key>StandardErrorPath</key>
  <string>{xml_escape(log_file)}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{xml_escape(env_path)}</string>
  </dict>
</dict>
</plist>
"""

    os.makedirs(os.path.dirname(LAUNCHD_PLIST), exist_ok=True)
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    with open(LAUNCHD_PLIST, "w") as f:
        f.write(plist)

    # bootstrap into the GUI domain for the current user
    uid = os.getuid()
    rc = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{uid}", LAUNCHD_PLIST],
        capture_output=True, text=True, check=False,
    )
    if rc.returncode != 0:
        print(f"launchctl bootstrap failed: {rc.stderr.strip()}", file=sys.stderr)
        return 1

    print(f"installed and loaded {LAUNCHD_PLIST}")
    print(f"running as: {' '.join(program_args)}")
    print(f"logs: {log_file}")
    return 0


def uninstall_launchd() -> int:
    """Unload and remove the launchd plist."""
    if not os.path.exists(LAUNCHD_PLIST):
        print(f"no plist at {LAUNCHD_PLIST}")
        return 0
    uid = os.getuid()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}/{LAUNCHD_LABEL}"],
        capture_output=True, text=True, check=False,
    )
    os.unlink(LAUNCHD_PLIST)
    print(f"removed {LAUNCHD_PLIST}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold",
        type=int,
        default=5000,
        help="open-file count that triggers a notification (default: 5000)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="seconds between checks (default: 30)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="number of top processes to track each cycle (default: 10)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print the top-N table on every cycle",
    )
    parser.add_argument(
        "--test-notification",
        action="store_true",
        help="send a sample notification and exit",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="detach and run in the background; logs go to --log-file",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="stop a running daemon (reads --pidfile) and exit",
    )
    parser.add_argument(
        "--install-launchd",
        action="store_true",
        help="install a launchd agent so the watcher auto-starts at login",
    )
    parser.add_argument(
        "--uninstall-launchd",
        action="store_true",
        help="unload and remove the launchd agent",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG,
        help=f"log file when running with --daemon (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--pidfile",
        default=DEFAULT_PIDFILE,
        help=f"pidfile when running with --daemon (default: {DEFAULT_PIDFILE})",
    )
    parser.add_argument(
        "--snapshot-dir",
        default=DEFAULT_SNAPSHOT_DIR,
        help=(
            "directory where per-trip lsof snapshots are written; "
            f"set to '' to disable (default: {DEFAULT_SNAPSHOT_DIR})"
        ),
    )
    parser.add_argument(
        "--kill-ratio",
        type=float,
        default=0.70,
        help=(
            "system-wide FD-pressure ratio (kern.num_files / kern.maxfiles) at "
            "which the watcher will start killing matching processes "
            "(default: 0.70)"
        ),
    )
    parser.add_argument(
        "--kill-comm",
        default="claude",
        help=(
            "comm name (lsof 'c' field) eligible to be killed under FD pressure. "
            "Defaults to 'claude' — matches the Claude Code CLI but not the "
            "/Applications/Claude.app desktop client (comm 'Claude')."
        ),
    )
    parser.add_argument(
        "--no-kill",
        action="store_true",
        help="disable coercive kill action; only notify on FD pressure",
    )
    args = parser.parse_args()

    if args.test_notification:
        notify(
            "Open files threshold exceeded",
            "test (PID 0) has 99999 open files",
        )
        print("sent test notification (waiting up to 60s for click/dismiss)", flush=True)
        # The notify() thread is a daemon; wait briefly so a quick click can
        # still trigger reveal-in-Finder before the process exits.
        for t in threading.enumerate():
            if t is not threading.main_thread():
                t.join(timeout=60)
        return 0

    if args.stop:
        return stop_daemon(args.pidfile)

    if args.uninstall_launchd:
        return uninstall_launchd()

    if args.install_launchd:
        script_path = os.path.abspath(__file__)
        extra = _passthrough_args(sys.argv[1:])
        return install_launchd(script_path, args.log_file, extra)

    if args.daemon:
        print(
            f"watcher detaching; log: {args.log_file}  pidfile: {args.pidfile}",
            flush=True,
        )
        daemonize(args.log_file, args.pidfile)

    notified: set[int] = set()

    while True:
        try:
            counts, names, histograms, details = count_open_files()
        except FileNotFoundError:
            print("lsof not found; this tool requires macOS / Unix.", file=sys.stderr)
            return 1

        top = counts.most_common(args.top)
        pressure = system_fd_pressure()

        if args.verbose:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] top {args.top} by open files:", flush=True)
            for pid, n in top:
                print(f"  {n:>6}  {pid:>6}  {names.get(pid, '?')}", flush=True)
            if pressure is not None:
                num, cap = pressure
                print(
                    f"  system: {num}/{cap} ({num/cap:.1%}) "
                    f"kill_ratio={args.kill_ratio:.0%}",
                    flush=True,
                )

        live_pids = {pid for pid, _ in top}

        for pid, n in top:
            if n >= args.threshold and pid not in notified:
                name = names.get(pid, "unknown")
                snapshot_path = snapshot_process(
                    pid,
                    name,
                    n,
                    args.threshold,
                    histograms.get(pid, Counter()),
                    details.get(pid, []),
                    args.snapshot_dir,
                )
                title = "Open files threshold exceeded"
                message = f"{name} (PID {pid}) has {n} open files"
                if snapshot_path:
                    message += "\nClick to reveal snapshot in Finder"
                notify(title, message, reveal_path=snapshot_path)
                print(f"NOTIFY: {message}", flush=True)
                if snapshot_path:
                    print(f"SNAPSHOT: {snapshot_path}", flush=True)
                notified.add(pid)

        # Coercive action: under system-wide FD pressure, kill the highest-FD
        # matching process (one per cycle — re-evaluate next tick rather than
        # nuking every session at once).
        if not args.no_kill and pressure is not None:
            num, cap = pressure
            if num >= args.kill_ratio * cap:
                candidates = sorted(
                    (
                        (pid, n)
                        for pid, n in counts.items()
                        if names.get(pid) == args.kill_comm
                    ),
                    key=lambda x: x[1],
                    reverse=True,
                )
                if candidates:
                    target_pid, target_fds = candidates[0]
                    ratio = num / cap
                    print(
                        f"COERCIVE KILL: system at {num}/{cap} ({ratio:.1%} >= "
                        f"{args.kill_ratio:.0%}); killing {args.kill_comm} "
                        f"PID {target_pid} ({target_fds} FDs)",
                        flush=True,
                    )
                    outcome = kill_pid(target_pid)
                    title = f"Killed {args.kill_comm} (FD pressure)"
                    message = (
                        f"system FDs {ratio:.0%} of limit ({num}/{cap})\n"
                        f"{args.kill_comm} PID {target_pid} "
                        f"holding {target_fds} FDs — {outcome}"
                    )
                    notify(title, message)
                    print(f"KILL OUTCOME: {outcome}", flush=True)
                else:
                    print(
                        f"FD PRESSURE: system at {num}/{cap} ({num/cap:.1%}) "
                        f"but no '{args.kill_comm}' processes to kill",
                        flush=True,
                    )

        # Allow re-notification once a PID drops out of the top set or below threshold.
        notified &= live_pids
        notified = {pid for pid in notified if counts.get(pid, 0) >= args.threshold}

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
