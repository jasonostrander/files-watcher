# files-watcher

A macOS-only watchdog for the system's file-descriptor table.

It does two things on a 30-second interval:

1. **Notifies** when any single process crosses an open-file count threshold
   (default 5,000). Writes an `lsof` snapshot of the offender so you can find
   the leak after the fact.
2. **Kills** runaway processes when the **system-wide** FD table
   (`kern.num_files`) approaches its limit (`kern.maxfiles`). By default it
   targets Claude Code CLI processes, which can hold tens of thousands of
   directory descriptors during `find`-style walks in large monorepos —
   enough that two concurrent sessions can exhaust the kernel file table on
   default macOS settings (491,520).

Single-file Python script. No deps beyond stdlib + `lsof`. Optional:
[`alerter`](https://github.com/vjeantet/alerter) for nicer notifications
that support click-to-reveal-in-Finder.

## Why

macOS's `kern.maxfiles` (default 491,520) is a system-wide cap shared by
every process. Once it's exhausted, *no* process can open files or
`fork()` — Activity Monitor, Console, even `lsof` itself stop working, and
the Mac usually needs a hard reboot. A handful of pathological processes
can saturate the table in seconds.

This tool catches the runaway before that happens and kills the offender,
so you keep your session.

## Install

```bash
git clone <this-repo> ~/personal/files-watcher
cd ~/personal/files-watcher

# optional but recommended — clickable notifications
brew install alerter

# auto-start at login (preferred)
python3 watcher.py --install-launchd

# or run in foreground
python3 watcher.py --verbose
```

Logs go to `~/Library/Logs/files-watcher.log`. Snapshots of offending
processes go to `~/Library/Logs/files-watcher-snapshots/`.

## What it does on each cycle

1. Runs `lsof -F pcftn` once and aggregates open-file counts per PID.
2. Reads `kern.num_files` and `kern.maxfiles` via `libc.sysctlbyname` —
   not `subprocess`, because the watcher needs to keep working when
   `fork()` is failing.
3. **Per-PID notify**: any process at or above `--threshold` (default
   5,000) triggers a notification + snapshot to disk. The notification
   is clickable to reveal the snapshot in Finder.
4. **System-wide coercive kill**: if `kern.num_files / kern.maxfiles`
   crosses `--kill-ratio` (default 0.70), the watcher picks the
   highest-FD process whose comm name matches `--kill-comm`
   (default `claude`), sends `SIGTERM`, waits 3s, and `SIGKILL`s if it
   hasn't exited. One kill per cycle — re-evaluates next tick instead
   of nuking every session at once.

## Configuration

Common flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--threshold` | 5000 | Per-process FD count that triggers a notification |
| `--interval` | 30 | Seconds between cycles |
| `--top` | 10 | Number of top processes printed in `--verbose` mode |
| `--kill-ratio` | 0.70 | System FD pressure (`num_files/maxfiles`) at which to start killing |
| `--kill-comm` | `claude` | comm name (lsof `c` field) eligible to be killed |
| `--no-kill` | off | Disable coercive kill action; only notify |
| `--snapshot-dir` | `~/Library/Logs/files-watcher-snapshots` | Where snapshots are written; `''` to disable |
| `--verbose` | off | Print top-N + system FD pressure every cycle |

### Why `claude` (lowercase)?

The lsof comm name `claude` matches the Claude Code CLI binary
(`~/Library/Application Support/Claude/claude-code/.../claude.app/Contents/MacOS/claude`).
The macOS desktop app reports as `Claude` (capital C, comm name from the
bundle), so it's spared by the default. To target something else, override
`--kill-comm`.

## Lifecycle

```bash
launchctl list | grep files-watcher           # status when under launchd
tail -f ~/Library/Logs/files-watcher.log      # live log
launchctl kickstart -k gui/$(id -u)/local.files-watcher  # restart to pick up changes

python3 watcher.py --uninstall-launchd        # remove launchd agent
python3 watcher.py --test-notification        # smoke-test the notification path
```

## Layout

- [watcher.py](watcher.py) — everything lives here
- [CLAUDE.md](CLAUDE.md) — orientation for AI coding sessions; implementation notes that aren't useful to end users
- `~/Library/LaunchAgents/local.files-watcher.plist` — launchd agent (created by `--install-launchd`)
- `~/Library/Logs/files-watcher.log` — log file under launchd / `--daemon`
- `~/Library/Logs/files-watcher.pid` — pidfile under `--daemon`
- `~/Library/Logs/files-watcher-snapshots/` — per-trip lsof snapshots
