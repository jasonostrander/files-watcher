# files-watcher

macOS-only utility: polls `lsof` on an interval, ranks the top-N processes by open file descriptor count, and fires a native notification when any process crosses the threshold.

Single-file Python script. No dependencies beyond the stdlib and the system `lsof`. Optional: `terminal-notifier` for nicer notifications.

## Layout

- [watcher.py](watcher.py) — everything lives here
- `~/Library/LaunchAgents/local.files-watcher.plist` — launchd agent (created by `--install-launchd`)
- `~/Library/Logs/files-watcher.log` — default log when running under launchd or `--daemon`
- `~/Library/Logs/files-watcher.pid` — default pidfile when running under `--daemon`

## How to run

```
python3 watcher.py                      # foreground, defaults
python3 watcher.py --verbose            # foreground, prints top-N each cycle
python3 watcher.py --test-notification  # fire a sample banner and exit
python3 watcher.py --daemon             # detach (manual double-fork)
python3 watcher.py --stop               # stop a --daemon process
python3 watcher.py --install-launchd    # auto-start at login (preferred over --daemon)
python3 watcher.py --uninstall-launchd
```

Defaults: `--threshold 5000`, `--interval 30`, `--top 10`.

## Non-obvious bits

**Notifications: prefer `terminal-notifier` over `osascript`.** Clicks on `osascript`-posted notifications open Script Editor (because that's the bundle that "owns" them). `terminal-notifier` lets us set `-sender com.apple.Terminal` and pass no click action, so clicks just dismiss. `notify()` falls back to `osascript` if `terminal-notifier` isn't on PATH.

**Don't combine `--daemon` with launchd.** The script's `--daemon` does the classic double-fork. launchd expects to track the process directly — if we daemonize under it, launchd thinks we crashed and respawns. The launchd path runs the watcher in the foreground; launchd handles backgrounding via `StandardOutPath`/`StandardErrorPath`.

**The plist embeds PATH.** launchd starts agents with a minimal PATH. The generated plist sets PATH to include `~/.rbenv/shims`, `/opt/homebrew/bin`, etc., so `shutil.which("terminal-notifier")` resolves at runtime. If the user installs `terminal-notifier` somewhere else, the install path needs updating.

**`lsof -F pcn`** is the fast path. Plain `lsof` is human-formatted; `-F pcn` returns one field per line tagged with `p` (pid), `c` (command name), `n` (name/path) — easy to parse and ~10x cheaper than parsing the default columnar output.

**Re-notification logic:** once a PID fires a notification, it's added to a `notified` set and won't re-notify until it either (a) drops out of the top-N or (b) drops below the threshold. Prevents spam from a process that legitimately holds many files.

## Stopping / status

```
launchctl list | grep files-watcher       # status when running under launchd
tail -f ~/Library/Logs/files-watcher.log  # live log
```
