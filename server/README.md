# Your own tunnel server

When you sign in on a computer with PassKeyChain, the phone and the browser
need a meeting point on the internet: a **tunnel server**. Both connect to
it, and it passes their messages back and forth. By default that is Google's
`cable.ua5v.com`. With these two scripts you can run your own.

What it gives you:

- **Independence:** sign-ins do not depend on Google's server.
- **Privacy:** Google no longer sees when and from which IP addresses you
  sign in.

What it does not change:

- **What the server can see:** sign-ins are end-to-end encrypted between
  phone and browser, on Google's server and on yours alike. The server cannot
  read or change them; it only sees that a connection happened.
- **The QR code:** you still scan one every time.

**Status:** both scripts are tested against a standard WebSocket client (11
unit tests, plus Node's built-in WebSocket as the browser). Not tested yet
with a real phone and Chrome. PassKeyChain does not have the "Tunnel server"
setting yet.

## How the browser finds your server

The phone tells the browser which tunnel server it used, as a number in its
Bluetooth broadcast. Numbers 0–255 are a fixed list built into the browser
(0 is Google). For 256–65535 the browser **computes** the hostname from the
number, for example 266 → `cable.wufkweyy3uaxb.com`. You cannot choose the
name, only the number. So: find a number whose name is still free, and
register it.

This is Chromium's scheme (`tunnelserver::DecodeDomain`). Whether Safari and
Firefox also accept computed names is not known yet.

## 1. Find a free name

```sh
python3 tunnel-hostnames.py --self-test          # checks the algorithm against Chromium
python3 tunnel-hostnames.py --tld org --limit 20 # a few candidates
python3 tunnel-hostnames.py --check --limit 10   # looks them up (RDAP), prints 10 that seem free
python3 tunnel-hostnames.py --number 266         # one number
```

`--check` asks the registries through rdap.org, one name per second. "Seems
free" means the registry has no record; confirm at a registrar before you
rely on it. Register the part after `cable.` (for 266: `wufkweyy3uaxb.com`)
and remember the number.

## 2. Run the server

Python 3.9 or newer, standard library only:

```sh
python3 tunnel-server.py --port 8080   # listens on 127.0.0.1:8080
```

Browsers only connect over `wss://`, so the server needs TLS. The simplest
way is a reverse proxy that gets a certificate by itself, such as
[Caddy](https://caddyserver.com). Point the DNS of `cable.<name>` (an A
and/or AAAA record) at your machine, then use this `Caddyfile`:

```text
cable.wufkweyy3uaxb.com {
    reverse_proxy 127.0.0.1:8080
}
```

Without a proxy: `--host 0.0.0.0 --port 443 --tls-cert fullchain.pem
--tls-key privkey.pem` (and renew the certificate yourself).

As a systemd service (`/etc/systemd/system/cable-tunnel.service`):

```ini
[Unit]
Description=caBLE tunnel server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/cable-tunnel/tunnel-server.py --port 8080
DynamicUser=yes
Restart=always

[Install]
WantedBy=multi-user.target
```

Check: `https://cable.<name>/health` answers "caBLE tunnel server".

## What the server does

| Path | Who | What |
|---|---|---|
| `/cable/new/<tunnel id>` | phone | waits for its browser; the answer has header `X-Cable-Routing-Id` |
| `/cable/connect/<routing id>/<tunnel id>` | browser | paired with that waiting phone; then all messages are forwarded |
| `/cable/contact/...` | browser | 410: linked phones; current Chrome no longer links phones from a QR code |
| `/` or `/health` | you | a short text, to check that it runs |

Limits:

- A phone waits at most 5 minutes for its browser.
- A tunnel stays open at most 10 minutes.
- At most 1000 phones wait at the same time.
- A message is at most 1 MiB.

It logs routing ids and timings, and client IP addresses only with
`--log-addresses`. It keeps nothing on disk.

## Tests

```sh
python3 -m unittest -v
```
