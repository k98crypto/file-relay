# File Relay — password-protected public file drop

A zero-dependency Python (stdlib only) file relay: one password, one page,
chunked uploads, share links. Built to hand files to a machine whose
clipboard doesn't work — upload from a browser, download on the other side.

## How it works

- `relay-server.py` serves on port 8899. No login page for LAN peers
  (`192.168.10.0/24`) and loopback; everyone else logs in with the password
  from the password file and gets a 30-day HMAC-signed session cookie.
- Public IPs that logged in once are remembered for 7 days.
- Uploads are chunked (16 MB pieces) so files larger than Cloudflare's
  100 MB single-request limit pass through a tunnel.
- `/s/<token>` is a public, revocable share download link.
- `relay-cleanup.py` removes stale uploads. Login brute force is rate
  limited (5 failures per IP per 15 minutes).

## Configure

Edit the constants at the top of `relay-server.py`:

```python
BASE      = "~/home-server/relay"   # files/ + shares.json live here
PASS_FILE = "~/home-server/.relay_pass"
PORT      = 8899
```

## Run

```bash
python3 relay-server.py
```

## License

MIT — see `LICENSE`.
