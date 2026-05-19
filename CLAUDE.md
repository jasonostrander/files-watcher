# files-watcher

macOS-only utility: polls `lsof` on an interval, ranks the top-N processes by open file descriptor count, and fires a native notification when any process crosses the threshold.

Single-file Python script. No dependencies beyond the stdlib and the system `lsof`. Optional: `alerter` for nicer notifications.

## Layout

- [watcher.py](watcher.py) — everything lives here
- `~/Library/LaunchAgents/local.files-watcher.plist` — launchd agent (created by `--install-launchd`)
- `~/Library/Logs/files-watcher.log` — default log when running under launchd or `--daemon`
- `~/Library/Logs/files-watcher.pid` — default pidfile when running under `--daemon`
- `~/Library/Logs/files-watcher-snapshots/` — per-trip `lsof` snapshots (created on first trip)

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

**Notifications: prefer `alerter` over `osascript`.** Clicks on `osascript`-posted notifications open Script Editor (because that's the bundle that "owns" them). `alerter` (vjeantet/alerter, arm64-native, actively maintained) lets us set `--sender com.apple.Terminal` for nicer attribution while still receiving click events on its own delegate. `notify()` falls back to `osascript` if `alerter` isn't on PATH. We previously used `terminal-notifier` here, but its binary is x86_64-only and runs under Rosetta — Apple has announced Rosetta will be removed in a future macOS, hence the swap.

**Click-to-reveal in Finder.** `notify()` accepts an optional `reveal_path`. When set, alerter is run in a daemon thread (alerter blocks until the user clicks/dismisses/times out), and on `@CONTENTCLICKED` we shell out to `open -R <path>` to reveal the file in Finder. This works alongside `--sender com.apple.Terminal` because alerter's `NSUserNotificationCenterDelegate` (see `Sources/Alerter/NotificationManager.swift` in the upstream repo) handles the activation regardless of the spoofed bundle ID — *as long as the alerter process is still alive when the user clicks*. If alerter has already exited (e.g. on watcher restart), the notification falls back to launching the spoofed bundle (Terminal) instead.

**Don't combine `--daemon` with launchd.** The script's `--daemon` does the classic double-fork. launchd expects to track the process directly — if we daemonize under it, launchd thinks we crashed and respawns. The launchd path runs the watcher in the foreground; launchd handles backgrounding via `StandardOutPath`/`StandardErrorPath`.

**The plist embeds PATH.** launchd starts agents with a minimal PATH. The generated plist sets PATH to include `~/.rbenv/shims`, `/opt/homebrew/bin`, etc., so `shutil.which("terminal-notifier")` resolves at runtime. If the user installs `terminal-notifier` somewhere else, the install path needs updating.

**`lsof -F pcftn`** is the fast path. Plain `lsof` is human-formatted; `-F pcftn` returns one field per line tagged with `p` (pid), `c` (command name), `f` (fd number), `t` (type), `n` (name/path) — easy to parse and much cheaper than parsing the default columnar output. The `f`/`t`/`n` triple per FD lets us build the per-PID histogram and detail listing in the same pass that detects breaches.

**Re-notification logic:** once a PID fires a notification, it's added to a `notified` set and won't re-notify until it either (a) drops out of the top-N or (b) drops below the threshold. Prevents spam from a process that legitimately holds many files.

**Snapshot on threshold trip.** When a PID first crosses threshold, `snapshot_process()` writes a TYPE histogram and per-FD detail to `--snapshot-dir` (default `~/Library/Logs/files-watcher-snapshots/`) using data captured during the detection scan itself — no follow-up `lsof -p <pid>` is needed, so the snapshot is complete even if the offending process exits immediately after detection. The histogram answers *what kind* of FDs blew up at a glance — e.g. a wall of `PIPE` rows points at a subprocess leak, a wall of `KQUEUE` rows points at file watchers. Pass `--snapshot-dir ""` to disable.

## Stopping / status

```
launchctl list | grep files-watcher       # status when running under launchd
tail -f ~/Library/Logs/files-watcher.log  # live log
```
