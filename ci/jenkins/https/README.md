# Serving Jenkins over HTTPS (fixes "insecure download blocked")

## The problem

Chrome and Brave **block downloads of archives** (`.zip`, `.xlsx`, …) that are
served over plain **HTTP**. When Jenkins runs on `http://<host>:8080`, clicking
the htmlpublisher **"Zip"** button on a published report shows:

> Insecure download blocked — This site isn't using a secure connection and the
> file may have been tampered with.

This is a browser security policy tied to the **HTTP origin** — it is not caused
by the report's contents or filename, and no change inside oxide-sloc can lift it
for the Zip button. The only complete fix is to serve Jenkins over **HTTPS**.

## Two layers of fix

1. **In-page workaround (already shipped, no setup needed).** The oxide-sloc CI
   dashboard's **Report & Exports** card downloads each artifact through a
   `blob:` URL, which the browser treats as a first-party origin — so those
   downloads work even over plain HTTP. **Use those links instead of the
   top-right "Zip" button.** This needs nothing from you.

2. **HTTPS (this folder) — the durable fix.** Put Jenkins behind a TLS reverse
   proxy. Once Jenkins is an `https://` origin, *every* download works, including
   the Zip button, with no warning.

## Pick one proxy

| File | Use when |
|------|----------|
| [`Caddyfile`](Caddyfile) | Easiest. Automatic certs (Let's Encrypt for a real domain, or a locally-trusted internal CA for a homelab IP/`.lan` name). |
| [`nginx-jenkins.conf`](nginx-jenkins.conf) | You already run nginx. Uses a self-signed cert (browsers warn once, then trust). |

Both are commented with exact steps. After the proxy is up:

1. Point it at the Jenkins port (`8080`), edit the address/cert paths to match.
2. Set **Manage Jenkins → System → Jenkins URL** to the new `https://…` address
   so generated links and the `BUILD_URL` used by the reports are correct.
3. Reload Jenkins config / the proxy.

### Homelab note (self-signed / internal CA)

For a LAN address like `https://10.0.0.8`, the certificate won't be publicly
trusted, so the browser prompts once. Accept it (or import Caddy's local CA /
the nginx `jenkins.crt` into the OS/browser trust store). After that it's a full
secure context and the download block is gone permanently.
