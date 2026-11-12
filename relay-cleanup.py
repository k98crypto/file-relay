#!/usr/bin/env python3
"""Part B: delete the test files from part A and verify 404s (file + share).
Prints PASS/FAIL only - never the password or the session cookie.
"""
import base64, http.client, json, os, socket as _socket, ssl, sys, urllib.parse

# 同 relay-test.py：服务器 IPv6 出站到 Cloudflare 不通，强制优先 IPv4。
_orig_gai = _socket.getaddrinfo


def _gai_ipv4_first(*args, **kwargs):
    res = _orig_gai(*args, **kwargs)
    return sorted(res, key=lambda r: r[0] != _socket.AF_INET)


_socket.getaddrinfo = _gai_ipv4_first

HOST = "dl.spiritwave.dpdns.org"
PASS_FILE = os.path.expanduser("~/home-server/.relay_pass")
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" | " + str(extra)) if (extra and not cond) else ""))


def req(method, path, body=None, headers=None):
    conn = http.client.HTTPSConnection(HOST, 443, context=ssl.create_default_context(), timeout=30)
    h = dict(headers or {})
    b = body
    if isinstance(b, dict):
        b = json.dumps(b).encode()
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=b, headers=h)
    r = conn.getresponse()
    data = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, hdrs, data


def main():
    with open(PASS_FILE) as f:
        pw = f.read().strip()
    with open("/tmp/relay-share-path") as f:
        share_path = f.read().strip()

    with open(PASS_FILE) as f:
        pw = f.read().strip()
    basic = "Basic " + base64.b64encode(("bonjour:" + pw).encode()).decode()
    H = {"Authorization": basic}
    s, _, d = req("GET", "/", headers=H)
    check("basic authed ok", s == 200 and "文件网盘".encode() in d, s)

    for name in ("relay-test-delete-me.bin", "网盘测试-请删除.txt"):
        s, _, _ = req("POST", "/api/delete", {"name": name}, headers=H)
        check("delete " + name, s == 200, s)
    s, _, _ = req("GET", "/f/relay-test-delete-me.bin", headers=H)
    check("deleted file 404", s == 404, s)
    s, _, _ = req("GET", share_path)
    check("share revoked after delete", s == 404, s)
    try:
        os.remove("/tmp/relay-share-path")
    except OSError:
        pass

    failed = [n for n, ok in results if not ok]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
