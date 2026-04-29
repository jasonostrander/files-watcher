#!/usr/bin/env python3
"""Monitor top processes by open file count and notify when one exceeds a threshold."""

import argparse
import errno
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter


def count_open_files() -> Counter:
    """Return a Counter mapping PID -> open file descriptor count."""
    # -n: no DNS resolution (fast). -P: numeric ports. -w: suppress warnings.
    # -F pn: machine-readable, only PID and command name fields per record.
    result = subprocess.run(
        ["lsof", "-n", "-P", "-w", "-F", "pcn"],
        capture_output=True,
        text=True,
        check=False,
    )

    counts: Counter = Counter()
    names: dict[int, str] = {}
    current_pid: int | None = None
    current_name: str | None = None

    for line in result.stdout.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            try:
                current_pid = int(value)
            except ValueError:
                current_pid = None
            current_name = None
        elif tag == "c" and current_pid is not None:
            current_name = value
            names[current_pid] = value
        elif tag == "n" and current_pid is not None:
            counts[current_pid] += 1

    # Attach names alongside counts via a side dict on the Counter.
    counts._names = names  # type: ignore[attr-defined]
    return counts


def notify(title: str, message: str) -> None:
    """Display a native macOS notification.

    Prefers terminal-notifier so clicking the banner doesn't launch Script Editor;
    falls back to osascript when terminal-notifier isn't installed.
    """
    tn = shutil.which("terminal-notifier")
    if tn:
        # No -activate / -execute / -open, so clicks just dismiss.
        # -sender attributes the banner (and icon) to Terminal.
        subprocess.run(
            [tn, "-title", title, "-message", message, "-sender", "com.apple.Terminal"],
            check=False,
        )
        return

    safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
    safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{safe_message}" with title "{safe_title}"'
    subprocess.run(["osascript", "-e", script], check=False)


DEFAULT_LOG = os.path.expanduser("~/Library/Logs/files-watcher.log")
DEFAULT_PIDFILE = os.path.expanduser("~/Library/Logs/files-watcher.pid")
LAUNCHD_LABEL = "local.files-watcher"
LAUNCHD_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist")


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
    args = parser.parse_args()

    if args.test_notification:
        notify(
            "Open files threshold exceeded",
            "test (PID 0) has 99999 open files",
        )
        print("sent test notification", flush=True)
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
            counts = count_open_files()
        except FileNotFoundError:
            print("lsof not found; this tool requires macOS / Unix.", file=sys.stderr)
            return 1

        top = counts.most_common(args.top)
        names: dict[int, str] = getattr(counts, "_names", {})

        if args.verbose:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] top {args.top} by open files:", flush=True)
            for pid, n in top:
                print(f"  {n:>6}  {pid:>6}  {names.get(pid, '?')}", flush=True)

        live_pids = {pid for pid, _ in top}

        for pid, n in top:
            if n >= args.threshold and pid not in notified:
                name = names.get(pid, "unknown")
                title = "Open files threshold exceeded"
                message = f"{name} (PID {pid}) has {n} open files"
                notify(title, message)
                print(f"NOTIFY: {message}", flush=True)
                notified.add(pid)

        # Allow re-notification once a PID drops out of the top set or below threshold.
        notified &= live_pids
        notified = {pid for pid in notified if counts.get(pid, 0) >= args.threshold}

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
