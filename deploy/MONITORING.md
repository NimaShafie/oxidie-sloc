# oxide-sloc — service, auto-restart, and down alerts (systemd)

The committed systemd unit already gives you **auto-start on boot** and
**auto-restart on crash**. This guide adds **email alerts when the server is down**
(both hard crashes and "process alive but not serving" hangs). No extra daemons —
just systemd, `curl`, and an SMTP relay you already have.

## What each piece does

| File | Role |
|------|------|
| `oxide-sloc.service` | The server. `Restart=on-failure` + `WantedBy=multi-user.target` = restart-on-crash and start-on-boot (already present). Now also `OnFailure=` fires a crash email. |
| `oxide-sloc-alert@.service` | Sends **one email when the service enters the failed state** (crashed and restart attempts were exhausted). |
| `oxide-sloc-health.service` + `.timer` | Every minute, probes `/healthz`. Emails on **down→up / up→down transitions only** — catches hangs the process-level restart can't see, without flooding. |
| `send-alert.sh` | SMTP-over-TLS sender via `curl`. Config from `alert.env`. |
| `healthcheck.sh` | Edge-triggered probe used by the timer. |
| `alert.env.example` | SMTP relay + from/to. Copy to `/etc/oxide-sloc/alert.env`. |

Two layers on purpose: `Restart=on-failure` recovers automatically, `OnFailure=`
tells you when recovery *failed*, and the health timer tells you when the process
is up but not actually serving (deadlock, wedged port, disk full).

## Install

```bash
# 1. Binary + assets (if not already deployed)
sudo install -m 0755 target/release/oxide-sloc /usr/local/bin/oxide-sloc
sudo mkdir -p /opt/oxide-sloc/deploy /opt/oxide-sloc/out
sudo useradd --system --home /opt/oxide-sloc --shell /usr/sbin/nologin oxide-sloc 2>/dev/null || true
sudo cp deploy/send-alert.sh deploy/healthcheck.sh /opt/oxide-sloc/deploy/
sudo chmod 0755 /opt/oxide-sloc/deploy/*.sh
sudo chown -R oxide-sloc:oxide-sloc /opt/oxide-sloc

# 2. Alert config (SMTP) — keep it non-world-readable, it holds a password
sudo mkdir -p /etc/oxide-sloc
sudo install -m 0640 -g oxide-sloc deploy/alert.env.example /etc/oxide-sloc/alert.env
sudoedit /etc/oxide-sloc/alert.env      # fill in real SMTP values

# 3. Units
sudo cp deploy/oxide-sloc.service deploy/oxide-sloc-alert@.service \
        deploy/oxide-sloc-health.service deploy/oxide-sloc-health.timer \
        /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Enable the server (start on boot + restart on crash) and the health timer
sudo systemctl enable --now oxide-sloc.service
sudo systemctl enable --now oxide-sloc-health.timer
```

`SLOC_API_KEY` etc. still go in `oxide-sloc.service` (or a dropin) as today — server
mode refuses to start without it.

## Test the alerts

```bash
# Hard-crash path: kill the server; OnFailure should email once after restarts fail.
sudo systemctl kill -s SIGKILL oxide-sloc && sleep 30 && systemctl status oxide-sloc

# Health path: stop the server so /healthz fails, wait for the timer, expect a DOWN mail;
# start it again and expect a RECOVERED mail.
sudo systemctl stop oxide-sloc      # DOWN email within ~1 min
sudo systemctl start oxide-sloc     # RECOVERED email within ~1 min

# Send-path smoke test (bypasses systemd):
sudo -u oxide-sloc bash -c 'set -a; . /etc/oxide-sloc/alert.env; \
  /opt/oxide-sloc/deploy/send-alert.sh "[oxide-sloc] test" "hello from $(hostname)"'
```

## Notes

- **Whole-box outage**: if the *machine* dies, on-host alerting can't email you.
  For that, also point an off-host probe (Uptime Kuma / Healthchecks.io / a cron on
  another server) at `http://<host>:4317/healthz`. The two are complementary.
- **STARTTLS relays**: use `ALERT_SMTP_URL=smtp://host:587`; `curl --ssl-reqd`
  upgrades the connection. Implicit TLS (465) uses `smtps://`.
- **Rate limiting**: `oxide-sloc-alert@.service` has `StartLimitBurst=3/300s` so a
  crash loop can't spam you; the health probe is edge-triggered for the same reason.
