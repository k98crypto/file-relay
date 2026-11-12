#!/usr/bin/env python3
"""File netdisk (dl.spiritwave.dpdns.org -> :8899). v3, 2026-10-22.

Auth model (unchanged from v2, same pattern as FABE console):
- Browser: form login at /login -> signed session cookie, 30 days.
- Preemptive Basic Auth still accepted (curl -u, scripts).
- No login needed: direct LAN peers (192.168.10.0/24), loopback direct,
  and public IPs that completed one good login are remembered 7 days.
- Login rate limit: 5 failed attempts per IP per 15 min -> 429.

Netdisk (new in v3):
- / : file list + chunked upload + delete + share-link management (authed).
- /api/upload/init, /api/upload/chunk, /api/upload/finish: chunked upload
  (browser slices into 16 MB pieces) so files larger than Cloudflare's
  100 MB single-request limit pass through the tunnel.
- /api/delete, /api/share, /api/unshare (authed).
- /s/<token> : public share download, no login. Token is random and
  unguessable; revocable from the management page. Old /s.ps1 routes
  keep working exactly as before.
- Downloads stream from disk with single-Range support (resumable,
  no whole-file RAM).
Files live in ~/home-server/relay/files/
"""
import base64, hashlib, hmac, html, ipaddress, json, os, re, secrets, shutil, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

BASE = os.path.expanduser("~/home-server/relay")
FILES_DIR = os.path.join(BASE, "files")
UPLOAD_DIR = os.path.join(BASE, ".uploads")
PASS_FILE = os.path.expanduser("~/home-server/.relay_pass")
LEARN_FILE = os.path.join(BASE, "learned_ips.json")
SHARE_FILE = os.path.join(BASE, "shares.json")
USERNAME = "bonjour"
LAN_NET = ipaddress.ip_network("192.168.10.0/24")
LEARN_TTL = 7 * 24 * 3600
COOKIE_TTL = 30 * 24 * 3600
COOKIE_NAME = "relay_session"
PORT = 8899
CHUNK_MAX = 32 * 1024 * 1024
STALE_UPLOAD_TTL = 24 * 3600
LOGIN_FAIL_WINDOW = 15 * 60
LOGIN_FAIL_MAX = 5

os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
_lock = threading.Lock()
_login_fails = {}


def load_password():
    try:
        with open(PASS_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def make_token():
    exp = int(time.time()) + COOKIE_TTL
    sig = hmac.new(load_password().encode(), ("relay:%d" % exp).encode(), hashlib.sha256).hexdigest()
    return "%d.%s" % (exp, sig)


def valid_token(tok):
    try:
        exp_s, sig = tok.split(".", 1)
        exp = int(exp_s)
        if exp < time.time():
            return False
        want = hmac.new(load_password().encode(), ("relay:%d" % exp).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, want)
    except Exception:
        return False


def load_learned():
    try:
        with open(LEARN_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def is_learned(ip):
    if not ip or ":" in ip:  # IPv4 only
        return False
    with _lock:
        ts = load_learned().get(ip)
        return bool(ts and time.time() - ts < LEARN_TTL)


def learn(ip):
    if not ip or ":" in ip:
        return
    with _lock:
        d = load_learned()
        d[ip] = time.time()
        d = {k: v for k, v in d.items() if time.time() - v < LEARN_TTL}
        tmp = LEARN_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, LEARN_FILE)


def load_shares():
    try:
        with open(SHARE_FILE) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_shares(d):
    # caller holds _lock
    tmp = SHARE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SHARE_FILE)


def safe_name(name):
    if not name:
        return ""
    n = unquote(name).replace("\\", "/").split("/")[-1].strip()
    if n in ("", ".", "..") or "\x00" in n or len(n) > 200:
        return ""
    return n


def unique_name(name):
    if not os.path.exists(os.path.join(FILES_DIR, name)):
        return name
    stem, ext = os.path.splitext(name)
    i = 1
    while True:
        cand = "%s (%d)%s" % (stem, i, ext)
        if not os.path.exists(os.path.join(FILES_DIR, cand)):
            return cand
        i += 1


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def upload_dir(uid):
    return os.path.join(UPLOAD_DIR, uid)


def prune_stale_uploads():
    now = time.time()
    try:
        for uid in os.listdir(UPLOAD_DIR):
            d = upload_dir(uid)
            try:
                if os.path.isdir(d) and now - os.path.getmtime(d) > STALE_UPLOAD_TTL:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass
    except OSError:
        pass


def read_meta(uid):
    try:
        with open(os.path.join(upload_dir(uid), "meta.json")) as f:
            return json.load(f)
    except Exception:
        return None


def write_meta(uid, meta):
    d = upload_dir(uid)
    tmp = os.path.join(d, "meta.json.tmp")
    with open(tmp, "w") as f:
        json.dump(meta, f)
    os.replace(tmp, os.path.join(d, "meta.json"))


def login_blocked(ip):
    now = time.time()
    lst = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]
    _login_fails[ip] = lst
    return len(lst) >= LOGIN_FAIL_MAX


def note_login_fail(ip):
    _login_fails.setdefault(ip, []).append(time.time())


LOGIN_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>登录 - 文件网盘</title><style>
body{font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 16px;line-height:1.6}
input{width:100%;padding:10px;margin:6px 0 14px;box-sizing:border-box;font-size:16px}
button{background:#0b5fff;color:#fff;border:0;padding:11px 0;width:100%;border-radius:8px;font-size:16px;cursor:pointer}
.err{color:#c00}</style></head><body>
<h2>文件网盘 - 登录</h2>__ERR__
<form method="post" action="/login">
<label>用户名</label><input name="u" autocomplete="username" required>
<label>密码</label><input name="p" type="password" autocomplete="current-password" required>
<button type="submit">登录</button></form>
<p style="color:#666;font-size:14px">登录一次后本浏览器 30 天免登录。家里局域网直连 http://192.168.10.10:8899 免登录。给朋友发文件不用给密码，用文件后面的“分享链接”就行。</p>
</body></html>"""

NETDISK_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>文件网盘</title><style>
body{font-family:sans-serif;max-width:900px;margin:24px auto;padding:0 16px;line-height:1.6}
table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #ddd;padding:8px 6px;text-align:left;vertical-align:top}
button{background:#0b5fff;color:#fff;border:0;padding:6px 14px;border-radius:6px;font-size:14px;cursor:pointer}
button.danger{background:#c0392b}
button.ghost{background:#eee;color:#333}
.muted{color:#666;font-size:13px}
.share{background:#f4f8ff;border-radius:6px;padding:6px 10px;margin-top:6px;word-break:break-all;font-size:14px}
#drop{border:2px dashed #0b5fff;border-radius:10px;padding:24px;text-align:center;color:#444;margin:16px 0}
#drop.over{background:#eef4ff}
.up-item{margin:8px 0}
.up-item progress{width:320px;max-width:70%}
code{background:#eee;padding:2px 6px;border-radius:4px}
</style></head><body>
<h2>文件网盘</h2>
<p><a href="/logout">退出登录</a> · <a href="/vm-setup">虚拟机脚本页（旧）</a></p>
<div id="drop">把文件拖到这里上传，或 <input type="file" id="file-input" multiple></div>
<div id="up-list"></div>
<h3>文件列表</h3>
<table><tr><th>文件名</th><th>大小</th><th>修改时间</th><th>操作</th></tr>__ROWS__</table>
<p class="muted">说明：大文件自动分片上传（16MB 一片），能过 Cloudflare 单请求 100MB 的限制；下载支持断点续传。分享链接无需登录即可下载，长期有效，直到你点“撤销”；删文件会同时作废它的分享链接。管理密码只给你自己用，朋友不用要密码。传输走 HTTPS，文件存在家里服务器硬盘上。</p>
<script>
function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtSize(n){var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return (i===0?Math.round(n)+' B':n.toFixed(1)+' '+u[i]);}
function copyText(t){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(function(){alert('已复制：\\n'+t);});}else{var ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);alert('已复制：\\n'+t);}}
async function postJSON(url,obj){var r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj)});if(!r.ok){var t=await r.text();throw new Error(t||('HTTP '+r.status));}return r.json();}
document.querySelectorAll('[data-ts]').forEach(function(el){el.textContent=new Date(parseInt(el.dataset.ts)*1000).toLocaleString();});
document.querySelectorAll('[data-share]').forEach(function(b){b.onclick=async function(){try{var r=await postJSON('/api/share',{name:b.dataset.share});alert('分享链接已生成，复制发给朋友就行：\\n'+r.url);location.reload();}catch(e){alert('生成失败：'+e.message);}};});
document.querySelectorAll('[data-del]').forEach(function(b){b.onclick=async function(){if(!confirm('确定删除 '+b.dataset.del+'？它的分享链接会同时失效。'))return;try{await postJSON('/api/delete',{name:b.dataset.del});location.reload();}catch(e){alert('删除失败：'+e.message);}};});
document.querySelectorAll('[data-unshare]').forEach(function(b){b.onclick=async function(){try{await postJSON('/api/unshare',{token:b.dataset.unshare});location.reload();}catch(e){alert('撤销失败：'+e.message);}};});
document.querySelectorAll('[data-copy]').forEach(function(b){b.onclick=function(){copyText(b.dataset.copy);};});
var CHUNK=16*1024*1024;
async function uploadOne(file,item){
  var bar=item.querySelector('progress'),st=item.querySelector('.st');
  st.textContent='准备上传…';
  var init=await postJSON('/api/upload/init',{name:file.name,size:file.size});
  var uid=init.upload_id,total=Math.ceil(file.size/CHUNK)||1;
  for(var i=0;i<total;i++){
    var blob=file.slice(i*CHUNK,(i+1)*CHUNK),ok=false;
    for(var a=0;a<3&&!ok;a++){var r=await fetch('/api/upload/chunk?upload_id='+encodeURIComponent(uid)+'&index='+i,{method:'POST',body:blob});ok=r.ok;}
    if(!ok)throw new Error('第 '+(i+1)+' 片上传失败');
    bar.value=Math.round((i+1)/total*100);
    st.textContent='上传中 '+(i+1)+'/'+total+' 片';
  }
  st.textContent='合并中…';
  var fin=await postJSON('/api/upload/finish',{upload_id:uid});
  st.textContent='完成：'+fin.name;
}
async function uploadFiles(files){
  var list=document.getElementById('up-list');
  for(var k=0;k<files.length;k++){
    var file=files[k],item=document.createElement('div');
    item.className='up-item';
    item.innerHTML='<div>'+escapeHtml(file.name)+'（'+fmtSize(file.size)+'）</div><progress value="0" max="100"></progress> <span class="st"></span>';
    list.appendChild(item);
    try{await uploadOne(file,item);}catch(e){item.querySelector('.st').textContent='失败：'+e.message;}
  }
  setTimeout(function(){location.reload();},800);
}
document.getElementById('file-input').addEventListener('change',function(){uploadFiles(this.files);});
var drop=document.getElementById('drop');
drop.addEventListener('dragover',function(e){e.preventDefault();drop.classList.add('over');});
drop.addEventListener('dragleave',function(){drop.classList.remove('over');});
drop.addEventListener('drop',function(e){e.preventDefault();drop.classList.remove('over');uploadFiles(e.dataTransfer.files);});
</script>
</body></html>"""

VM_PAGE_TMPL = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>文件中转 - Win11 虚拟机设置</title>
<style>body{font-family:sans-serif;max-width:860px;margin:24px auto;padding:0 16px;line-height:1.6}
pre{background:#111;color:#eee;padding:14px;overflow:auto;border-radius:8px;font-size:13px}
button,a.btn{background:#0b5fff;color:#fff;border:0;padding:10px 18px;border-radius:8px;font-size:16px;text-decoration:none;cursor:pointer}
code{background:#eee;padding:2px 6px;border-radius:4px}</style></head><body>
<p><a href="/">← 回网盘</a></p>
<h2>Win11 虚拟机 SSH 开通脚本</h2>
<ol>
<li>点下面按钮下载脚本到虚拟机里（或在管理员 PowerShell 里输：<code>irm http://192.168.10.10:8899/s.ps1 | iex</code>）</li>
<li>在虚拟机里打开<b>管理员 PowerShell</b>（右键开始菜单 → 终端(管理员)）</li>
<li>运行下载的脚本：<code>powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\winvm-setup.ps1"</code></li>
<li>跑完把输出里 <b>IP 那几行</b>截图发给 Jervis</li>
</ol>
<p><a class="btn" href="/f/winvm-setup.ps1">⬇ 下载 winvm-setup.ps1</a> &nbsp;<a href="/logout">退出登录</a></p>
<h3>中转文件列表</h3><ul>__ITEMS__</ul>
<h3>脚本全文（也可以在虚拟机浏览器里全选复制）</h3>
<button onclick="navigator.clipboard.writeText(document.getElementById('s').innerText)">复制脚本</button>
<pre id="s">__SCRIPT__</pre>
</body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    def real_ip(self):
        return self.headers.get("Cf-Connecting-IP") or self.client_address[0]

    def via_tunnel(self):
        return self.headers.get("Cf-Connecting-IP") is not None

    def cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith(COOKIE_NAME + "="):
                return part[len(COOKIE_NAME) + 1:]
        return ""

    def no_auth_needed(self):
        peer = ipaddress.ip_address(self.client_address[0])
        if peer.is_loopback and not self.via_tunnel():
            return True
        if peer in LAN_NET:
            return True
        if self.via_tunnel() and is_learned(self.real_ip()):
            return True
        return False

    def basic_ok(self):
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
            except Exception:
                return False
            if secrets.compare_digest(user, USERNAME) and secrets.compare_digest(pw, load_password()):
                learn(self.real_ip())
                return True
        return False

    def authed(self):
        return self.no_auth_needed() or valid_token(self.cookie_token()) or self.basic_ok()

    def send_bytes(self, data, ctype, filename=None, status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def send_json(self, obj, status=200):
        self.send_bytes(json.dumps(obj).encode(), "application/json", status=status)

    def redirect(self, loc, extra=None):
        h = {"Location": loc}
        h.update(extra or {})
        self.send_bytes(b"", "text/plain", status=303, extra=h)

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if n <= 0 or n > 1024 * 1024:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except Exception:
            return None

    def public_url(self, path):
        host = self.headers.get("Host", "dl.spiritwave.dpdns.org")
        scheme = "https" if self.via_tunnel() else "http"
        return "%s://%s%s" % (scheme, host, path)

    def send_file(self, path, filename, ctype, head_only=False):
        try:
            size = os.path.getsize(path)
        except OSError:
            self.send_error(404)
            return
        start, end, status = 0, size - 1, 200
        rh = self.headers.get("Range", "")
        if rh.startswith("bytes="):
            spec = rh[6:].split(",")[0].strip()
            try:
                if spec.startswith("-"):
                    start = max(0, size - int(spec[1:]))
                else:
                    a, _, b = spec.partition("-")
                    start = int(a) if a else 0
                    end = int(b) if b else size - 1
                if 0 <= start <= end < size:
                    status = 206
                else:
                    start, end, status = 0, size - 1, 200
            except ValueError:
                start, end, status = 0, size - 1, 200
        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''%s" % quote(filename))
        self.end_headers()
        if head_only:
            return
        with open(path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def share_entry(self, token):
        with _lock:
            d = load_shares()
            ent = d.get(token)
            if not ent:
                return None
            name = ent.get("file", "")
            p = os.path.join(FILES_DIR, name)
            if not os.path.isfile(p) or safe_name(name) != name:
                d.pop(token, None)
                save_shares(d)
                return None
            return p, name

    def share_download(self, token, head_only=False):
        got = self.share_entry(token)
        if not got:
            self.send_error(404)
            return
        p, name = got
        if not head_only:
            with _lock:
                d = load_shares()
                if token in d:
                    d[token]["downloads"] = d[token].get("downloads", 0) + 1
                    save_shares(d)
        self.send_file(p, name, "application/octet-stream", head_only=head_only)

    def netdisk_page(self):
        with _lock:
            shares = load_shares()
        by_file = {}
        for tok, ent in shares.items():
            by_file.setdefault(ent.get("file"), []).append((tok, ent))
        try:
            names = os.listdir(FILES_DIR)
        except OSError:
            names = []
        infos = []
        for n in names:
            p = os.path.join(FILES_DIR, n)
            if os.path.isfile(p):
                st = os.stat(p)
                infos.append((st.st_mtime, n, st.st_size))
        infos.sort(reverse=True)
        rows = []
        for mtime, n, size in infos:
            esc = html.escape(n)
            attr = html.escape(n, quote=True)
            row = ('<tr><td><a href="/f/%s">%s</a></td><td>%s</td>'
                   '<td><span data-ts="%d"></span></td>'
                   '<td><button data-share="%s">分享链接</button> '
                   '<button class="danger" data-del="%s">删除</button></td></tr>') % (
                       quote(n), esc, human_size(size), int(mtime), attr, attr)
            rows.append(row)
            for tok, ent in by_file.get(n, []):
                url = self.public_url("/s/" + tok)
                rows.append(('<tr><td colspan="4"><div class="share">🔗 '
                             '<a href="%s">%s</a> '
                             '<button class="ghost" data-copy="%s">复制</button> '
                             '<button class="ghost" data-unshare="%s">撤销</button> '
                             '<span class="muted">已下载 %d 次</span></div></td></tr>') % (
                                 html.escape(url), html.escape(url), html.escape(url, quote=True),
                                 tok, ent.get("downloads", 0)))
        return NETDISK_PAGE.replace("__ROWS__", "".join(rows)).encode("utf-8")

    def vm_page(self):
        try:
            files = sorted(os.listdir(FILES_DIR))
        except OSError:
            files = []
        items = "".join(
            '<li><a href="/f/%s">%s</a> (%d KB)</li>' % (quote(f), html.escape(f), max(1, os.path.getsize(os.path.join(FILES_DIR, f)) // 1024))
            for f in files if os.path.isfile(os.path.join(FILES_DIR, f)))
        script = ""
        sp = os.path.join(FILES_DIR, "winvm-setup.ps1")
        if os.path.isfile(sp):
            with open(sp, encoding="utf-8", errors="replace") as f:
                script = html.escape(f.read())
        return VM_PAGE_TMPL.replace("__ITEMS__", items).replace("__SCRIPT__", script).encode("utf-8")

    # ---- routing ----

    def do_GET(self):
        raw_path = urlparse(self.path).path
        path = unquote(raw_path).replace("\\", "/")
        # tolerate hand-typed variants: /s, /s.ps1\iex, /s.ps1/iex, /s.ps1|iex, /s.ps1iex
        if re.match(r"^/s(\.ps1)?(/?\|?iex)?$", path):
            path = "/s.ps1"
        if path == "/health":
            return self.send_bytes(b"OK", "text/plain")
        if path == "/favicon.ico":
            return self.send_bytes(b"", "image/x-icon")
        if path == "/logout":
            return self.redirect("/login", {"Set-Cookie": COOKIE_NAME + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"})
        if path == "/login":
            if self.authed():
                return self.redirect("/")
            return self.send_bytes(LOGIN_PAGE.replace("__ERR__", "").encode(), "text/html; charset=utf-8")
        m = re.match(r"^/s/([A-Za-z0-9_-]{24,})$", path)
        if m:
            return self.share_download(m.group(1))
        if not self.authed():
            return self.redirect("/login")
        if path in ("/s.ps1", "/s2.ps1"):
            fn = "winvm-setup2.ps1" if "2" in path else "winvm-setup.ps1"
            p = os.path.join(FILES_DIR, fn)
            if os.path.isfile(p):
                return self.send_file(p, fn, "text/plain; charset=utf-8")
            self.send_error(404)
            return
        if path.startswith("/f/"):
            name = safe_name(path[3:])
            if not name:
                self.send_error(404)
                return
            p = os.path.join(FILES_DIR, name)
            if os.path.isfile(p):
                return self.send_file(p, name, "application/octet-stream")
            self.send_error(404)
            return
        if path == "/vm-setup":
            return self.send_bytes(self.vm_page(), "text/html; charset=utf-8")
        if path == "/":
            return self.send_bytes(self.netdisk_page(), "text/html; charset=utf-8")
        self.send_error(404)

    def do_HEAD(self):
        raw_path = urlparse(self.path).path
        path = unquote(raw_path).replace("\\", "/")
        m = re.match(r"^/s/([A-Za-z0-9_-]{24,})$", path)
        if m:
            return self.share_download(m.group(1), head_only=True)
        if not self.authed():
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/f/"):
            name = safe_name(path[3:])
            if name:
                p = os.path.join(FILES_DIR, name)
                if os.path.isfile(p):
                    return self.send_file(p, name, "application/octet-stream", head_only=True)
        self.send_error(404)

    def handle_login(self):
        ip = self.real_ip()
        if login_blocked(ip):
            return self.send_bytes(LOGIN_PAGE.replace("__ERR__", '<p class="err">失败次数太多，15 分钟后再试。</p>').encode(),
                                    "text/html; charset=utf-8", status=429)
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace")) if n > 0 else {}
        user = form.get("u", [""])[0]
        pw = form.get("p", [""])[0]
        if secrets.compare_digest(user, USERNAME) and secrets.compare_digest(pw, load_password()):
            _login_fails.pop(ip, None)
            learn(ip)
            cookie = "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (COOKIE_NAME, make_token(), COOKIE_TTL)
            return self.redirect("/", {"Set-Cookie": cookie})
        note_login_fail(ip)
        return self.send_bytes(LOGIN_PAGE.replace("__ERR__", '<p class="err">用户名或密码不对，再试一次。</p>').encode(),
                                "text/html; charset=utf-8", status=401)

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        if path == "/login":
            return self.handle_login()
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, status=401)
        if path == "/api/upload/init":
            return self.api_upload_init()
        if path == "/api/upload/chunk":
            return self.api_upload_chunk()
        if path == "/api/upload/finish":
            return self.api_upload_finish()
        if path == "/api/delete":
            return self.api_delete()
        if path == "/api/share":
            return self.api_share()
        if path == "/api/unshare":
            return self.api_unshare()
        self.send_error(404)

    def api_upload_init(self):
        body = self.read_json()
        if not isinstance(body, dict):
            return self.send_json({"error": "bad request"}, status=400)
        name = safe_name(body.get("name", ""))
        try:
            size = int(body.get("size", 0))
        except (TypeError, ValueError):
            return self.send_json({"error": "bad size"}, status=400)
        if not name or size < 0:
            return self.send_json({"error": "bad name/size"}, status=400)
        try:
            free = shutil.disk_usage(FILES_DIR).free
        except OSError:
            free = 0
        if size > max(0, free - 2 * 1024 * 1024 * 1024):
            return self.send_json({"error": "磁盘空间不足"}, status=413)
        prune_stale_uploads()
        uid = secrets.token_urlsafe(16)
        os.makedirs(upload_dir(uid), exist_ok=True)
        write_meta(uid, {"name": name, "size": size, "chunks": []})
        return self.send_json({"upload_id": uid})

    def api_upload_chunk(self):
        qs = parse_qs(urlparse(self.path).query)
        uid = qs.get("upload_id", [""])[0]
        idx_s = qs.get("index", [""])[0]
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", uid) or not idx_s.isdigit():
            return self.send_json({"error": "bad upload"}, status=400)
        d = upload_dir(uid)
        meta = read_meta(uid)
        if meta is None or not os.path.isdir(d):
            return self.send_json({"error": "upload not found"}, status=404)
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self.send_json({"error": "bad length"}, status=400)
        if n < 0 or n > CHUNK_MAX:
            self.close_connection = True
            return self.send_json({"error": "chunk too large"}, status=413)
        data = self.rfile.read(n) if n else b""
        idx = int(idx_s)
        with open(os.path.join(d, str(idx)), "wb") as f:
            f.write(data)
        meta["chunks"] = sorted(set(meta.get("chunks", [])) | {idx})
        write_meta(uid, meta)
        return self.send_json({"ok": True, "chunks": len(meta["chunks"])})

    def api_upload_finish(self):
        body = self.read_json()
        if not isinstance(body, dict):
            return self.send_json({"error": "bad request"}, status=400)
        uid = body.get("upload_id", "")
        if not isinstance(uid, str) or not re.match(r"^[A-Za-z0-9_-]{1,64}$", uid):
            return self.send_json({"error": "bad upload"}, status=400)
        d = upload_dir(uid)
        meta = read_meta(uid)
        if meta is None or not os.path.isdir(d):
            return self.send_json({"error": "upload not found"}, status=404)
        chunks = sorted(meta.get("chunks", []))
        if chunks != list(range(len(chunks))):
            return self.send_json({"error": "chunks missing"}, status=400)
        total = 0
        for i in chunks:
            try:
                total += os.path.getsize(os.path.join(d, str(i)))
            except OSError:
                return self.send_json({"error": "chunk missing"}, status=400)
        if total != meta["size"]:
            return self.send_json({"error": "size mismatch"}, status=400)
        final = unique_name(meta["name"])
        dest = os.path.join(FILES_DIR, final)
        with open(dest, "wb") as out:
            for i in chunks:
                with open(os.path.join(d, str(i)), "rb") as f:
                    shutil.copyfileobj(f, out, 1024 * 1024)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        shutil.rmtree(d, ignore_errors=True)
        return self.send_json({"ok": True, "name": final, "size": total})

    def api_delete(self):
        body = self.read_json()
        name = safe_name(body.get("name", "")) if isinstance(body, dict) else ""
        if not name:
            return self.send_json({"error": "bad name"}, status=400)
        p = os.path.join(FILES_DIR, name)
        if not os.path.isfile(p):
            return self.send_json({"error": "not found"}, status=404)
        os.remove(p)
        with _lock:
            d = load_shares()
            d = {t: e for t, e in d.items() if e.get("file") != name}
            save_shares(d)
        return self.send_json({"ok": True})

    def api_share(self):
        body = self.read_json()
        name = safe_name(body.get("name", "")) if isinstance(body, dict) else ""
        if not name:
            return self.send_json({"error": "bad name"}, status=400)
        if not os.path.isfile(os.path.join(FILES_DIR, name)):
            return self.send_json({"error": "not found"}, status=404)
        token = secrets.token_urlsafe(24)
        with _lock:
            d = load_shares()
            d[token] = {"file": name, "created": int(time.time()), "downloads": 0}
            save_shares(d)
        return self.send_json({"ok": True, "token": token, "url": self.public_url("/s/" + token)})

    def api_unshare(self):
        body = self.read_json()
        token = body.get("token", "") if isinstance(body, dict) else ""
        if not isinstance(token, str) or not re.match(r"^[A-Za-z0-9_-]{24,}$", token):
            return self.send_json({"error": "bad token"}, status=400)
        with _lock:
            d = load_shares()
            if token not in d:
                return self.send_json({"error": "not found"}, status=404)
            del d[token]
            save_shares(d)
        return self.send_json({"ok": True})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    srv.daemon_threads = True
    srv.serve_forever()
