# sshpot

`sshpot` is a small, lightweight SSH honeypot written in Go.

It listens like a normal SSH service, accepts password auth attempts, logs them to CSV, and closes the session shortly after. It is designed to be simple to run and easy to reason about.

## What this is for

- Keep your real SSH service on another port.
- Let internet background noise hit the honeypot on port 22.
- Record login attempts and optionally auto-ban abusive sources.

This project is not trying to punish every internet scan. Scanning for research, curiosity, or inventory happens all the time.

However, (my) red line is active login attempts. If a host tries to authenticate against the honeypot, we can ban it for a while and report it to AbuseIPDB.

## Why this project

This is not a full fledged honeypot with a fake filesystem, interactive shell, or multiple auth methods. There exist plenty already. It is a simple SSH server that logs auth attempts and disconnects (this was the scope).

## How it behaves
(how secure is exposing this thing to the internet?)

1. Starts as root (systemd) so it can open the log file and bind low ports.
2. Binds the listening socket.
3. Drops privileges to the configured user/group.
4. For each connection:
   - generates a fresh Ed25519 host key specific to that session
   - performs SSH handshake,
   - accepts password auth,
   - logs attempt (`ip`, `username`, `password`, client version),
   - shows a fake shell banner/MOTD,
   - closes the channel.

   (timeouts and delays are configurable to make it more or less responsive)
  
A leaky bloom filter is used to rate limit connections by IP, so that bots that scan and try to authenticate at high speed get blocked after a few attempts (see [ratelimit](internal/ratelimit/ratelimit.go)).

## Requirements

- Linux
- Go 1.22+
- systemd (recommended)
- fail2ban + curl (optional, for bans + AbuseIPDB reports)

## Install

```bash
sudo make install
```

This installs:

- binary: `/usr/local/bin/sshpot`
- config: `/etc/sshpot/config.toml`
- service: `/etc/systemd/system/sshpot.service`
- logrotate: `/etc/logrotate.d/sshpot`
- fail2ban contrib files under `/etc/fail2ban/...`

`DESTDIR` may be specified to change the install root (for packaging or testing).

After installation, start the service:s

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sshpot
```

## Configuration

Main config: `/etc/sshpot/config.toml`

Important keys:

- `[server].listen` (example: `0.0.0.0:22`)
- `[server].handshake_timeout` (duration with unit, example: `10s`)
- `[server].shell_request_timeout` (duration with unit)
- `[server].pre_output_delay` (duration with unit)
- `[server].post_output_delay` (duration with unit)
- `[logging].path` (example: `/var/log/sshpot/logins.csv`)
- `[ratelimit].bucket_count`
- `[ratelimit].rest_interval` (duration with unit)
- `[process].user`, `[process].group`

All durations must be specified as strings with units (`500ms`, `2s`, `10m`, ...).

## Templates
In the config file, the `output_text` and `banner` fields support Go `text/template` syntax.

Available helper functions:

- `nowUTC()`: current UTC time formatted as "Mon Jan 2 15:04:05 UTC 2006".
- `randInt(min, max)`: random integer between `min` and `max` (inclusive).
- `randFloat(min, max)`: random float between `min` and `max`.
- `randPercent()`: random float in the range 0.0-100.0.
- `chance(percent)`: returns `true` with the given percent probability.
- `randDate(min, max)`: random date between `min` and `max`, formatted like "Mon Jan 2 15:04:05 2006".
- `diskSize(min, max)`: formatted size string in GB.
- `randIP("192.168.x.x")`: replace each `x` with a random 0-255 component.

This is used to make the fake shell banner and output more dynamic and less identical across sessions, which can help against simple bot heuristics. and can allow some artistry in the fake output if desired.

## Operational notes

**Treat captured credentials as sensitive data**: (credential stuffing often uses real leaked credentials, and some bots might be testing them against your real SSH service if it is on a common port).

## License

[MIT](LICENSE)