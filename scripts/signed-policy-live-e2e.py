#!/usr/bin/env python3
# Signed-policy live E2E (task #2568) against the real p3sig.com — the four DONE-WHEN cases:
#   (a) a change signed by a delegated device key (no root key) lands on a real sshd
#   (b) a tampered response (MITM with a CA the box trusts) injecting a CA is REJECTED, old CA kept
#   (c) a replayed older signed policy is rejected
#   (d) a revoked device's signature is rejected
# Everything is throwaway: a fresh account (xxxx@contactsweep.com), keys in a temp dir, a user-mode
# sshd on 127.0.0.1, and a local MITM proxy whose CA only this run's agent trusts (SSL_CERT_FILE).
#   python3 scripts/signed-policy-live-e2e.py [--bin ./p3sig-agent] [--base https://p3sig.com/p3sig]
# The device key is a software ed25519 key held in ssh-agent — the same path the dongle (ssh-add, sk)
# and the chip (p3sig ssh-agent) use; the hardware itself is not exercised here.
import argparse, base64, copy, getpass, http.client, http.cookiejar, json, os, re, secrets, shutil
import socket, ssl, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--bin", default=os.path.join(os.path.dirname(__file__), "..", "p3sig-agent"))
ap.add_argument("--base", default="https://p3sig.com/p3sig")
ap.add_argument("--keep", action="store_true", help="keep the temp dir")
A = ap.parse_args()
BIN = os.path.abspath(A.bin)
BASE = A.base.rstrip("/")
API = BASE + "/api/index.php"
HOST = urllib.parse.urlparse(BASE).hostname
T = tempfile.mkdtemp(prefix="p3sig-sp-e2e-")
OUT = os.path.join(T, "ssh")
fails = []
procs = []


def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        fails.append(what)


def sh(*cmd, env=None, ok=True, input=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, input=input)
    if ok and r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r


def p(name):
    return os.path.join(T, name)


# ── 1. account + vault key + machine + CA, through the web forms ─────────────
jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(path, **form):
    # The host throttles bursts (a fast run got a 502 on the 4th form post): space the posts
    # out and retry a gateway error once, slowly — never a tight loop.
    for attempt in (1, 2):
        time.sleep(2)
        try:
            r = web.open(BASE + path, urllib.parse.urlencode(form).encode())
            return r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code not in (502, 503) or attempt == 2:
                raise
            print(f"note: HTTP {e.code} on {path}, retrying once in 30s", flush=True)
            time.sleep(30)


# @contactsweep.com is a catch-all into the nokemo@nokemo.com inbox, which himalaya (account
# "nokemo") reads — so the live sign-up's confirmation mail can be followed like a real user would.
email = f"signedpolicy-{secrets.token_hex(4)}@contactsweep.com"
pw = "SignedPolicy-E2E-" + secrets.token_hex(6)
post("/auth/register.php", action="register", email=email, password=pw, confirm_password=pw, agree_terms="1")


def confirm_link(addr, wait=180):
    """Find the 'Confirm Your Account' mail sent to addr and return its auth/confirm.php link."""
    t0 = time.time()
    while time.time() - t0 < wait:
        r = sh("himalaya", "envelope", "list", "--account", "nokemo", "--output", "json", ok=False)
        try:
            envs = json.loads(r.stdout or "[]")
        except ValueError:
            envs = []
        for e in envs:
            if ((e.get("to") or {}).get("addr") or "").lower() == addr.lower() and "confirm" in (e.get("subject") or "").lower():
                body = sh("himalaya", "message", "read", str(e["id"]), "--account", "nokemo", ok=False).stdout
                m = re.search(r"https://[^\s\"'<>]+/auth/confirm\.php\?hash=[A-Za-z0-9%._-]+", body)
                if m:
                    return m.group(0)
        time.sleep(10)
    return None


link = confirm_link(email)
check(bool(link), f"confirmation mail for {email} arrived")
if not link:
    raise SystemExit("no confirmation mail within 3 min — stopping")
web.open(link).read()
post("/auth/login.php", action="login", email=email, password=pw)
_, body = post("/app/index.php?page=vault-setup", noop="1")
check("logout" in body.lower(), f"confirmed + logged in on {HOST} as {email}")
if fails:
    raise SystemExit("cannot sign in to the fresh account — stopping")

def keygen(name):
    out = sh(BIN, "keygen", "--out", p(name)).stdout
    return out.strip().splitlines()[-1].strip()

vault_pub = keygen("vault.key")
post("/app/index.php?page=vault-setup", action="addUserKey", label="e2e-vault", public_key=vault_pub)
machine_pub = keygen("machine.key")
url, _ = post("/app/index.php?page=machines", action="createMachine", name="sp-e2e-box", public_key=machine_pub)
m = re.search(r"machine_id=([^&#]+)", url)
check(bool(m), "machine created")
MID = m.group(1) if m else ""
for k in ("ca1", "evil", "root", "device", "user"):
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", p(k))
ca1 = open(p("ca1.pub")).read().strip()
post("/app/index.php?page=ssh-access", action="registerSshCa", name="e2e-ca1", public_key=ca1)
# A CA reaches a machine only through a principal grant (p3sig_policy_draft joins on grants).
me = getpass.getuser()
_, page = post("/app/index.php?page=ssh-access", noop="1")
cm = re.search(r'<option value="([^"]+)">e2e-ca1</option>', page)
check(bool(cm), "CA registered")
CAID = cm.group(1) if cm else ""
post("/app/index.php?page=ssh-access", action="grantSshPrincipal", ca_id=CAID, machine_id=MID,
     principal=me, login_user=me)

env = dict(os.environ, P3SIG_URL=API, P3SIG_VAULT_KEY=p("vault.key"), P3SIG_CONFIG=p("cfg.json"))
st = sh(BIN, "policy", "status", env=env, ok=False)
check(st.returncode == 0, "vault key authenticates the CLI (policy status)")

# ── 2. root (once, from the "safe"), delegate the device, sign with the device only ──
r = sh(BIN, "policy", "root", "--root-key", p("root"), env=env)
fp = re.search(r"SHA256:[A-Za-z0-9+/=]+", r.stdout)
ROOT = fp.group(0)
sh(BIN, "policy", "delegate", "--root-key", p("root"), "--device", p("device.pub"), "--label", "e2e-dongle", "--expires", "1d", env=env)

agent_env = dict(env)
a = sh("ssh-agent", "-s").stdout
agent_env["SSH_AUTH_SOCK"] = re.search(r"SSH_AUTH_SOCK=([^;]+)", a).group(1)
agent_pid = re.search(r"SSH_AGENT_PID=(\d+)", a).group(1)
sh("ssh-add", p("device"), env=agent_env)
os.rename(p("root"), p("root.safe"))      # the safe goes back in the drawer: no root key from here on


def sign():
    return sh(BIN, "policy", "sign", "--machine", MID, "--with", "agent", "--yes", env=agent_env, ok=False)


s1 = sign()
check(s1.returncode == 0, "device (in ssh-agent, no root key) signed policy v1")

# ── 3. MITM proxy: TLS for HOST from a local CA the agent is told to trust ────
sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
   "-subj", "/CN=e2e-mitm-ca", "-keyout", p("mitm-ca.key"), "-out", p("mitm-ca.pem"))
sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={HOST}",
   "-keyout", p("leaf.key"), "-out", p("leaf.csr"))
open(p("leaf.ext"), "w").write(f"subjectAltName=DNS:{HOST}\n")
sh("openssl", "x509", "-req", "-in", p("leaf.csr"), "-CA", p("mitm-ca.pem"), "-CAkey", p("mitm-ca.key"),
   "-CAcreateserial", "-days", "1", "-extfile", p("leaf.ext"), "-out", p("leaf.pem"))
leaf_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
leaf_ctx.load_cert_chain(p("leaf.pem"), p("leaf.key"))
MODE = {"m": "pass", "replay": None, "seen": []}


def find_signed(o):
    if isinstance(o, dict):
        if isinstance(o.get("policy"), dict) and "payload" in o["policy"]:
            return o
        for v in o.values():
            f = find_signed(v)
            if f is not None:
                return f
    return None


def tamper(raw):
    data = json.loads(raw)
    sp = find_signed(data)
    if sp is None:
        return raw
    MODE["seen"].append(copy.deepcopy(data))
    if MODE["m"] == "inject":                      # attacker adds its CA, cannot re-sign
        pol = json.loads(base64.b64decode(sp["policy"]["payload"]))
        pol["trusted_user_ca_keys"].append(open(p("evil.pub")).read().strip())
        sp["policy"]["payload"] = base64.b64encode(json.dumps(pol).encode()).decode()
    elif MODE["m"] == "unsigned":                  # attacker strips the signature entirely
        return json.dumps({"signed": False}).encode()
    elif MODE["m"] == "replay":
        return json.dumps(MODE["replay"]).encode()
    return json.dumps(data).encode()


def handle(c):
    try:
        f = c.makefile("rb")
        line = f.readline().decode()
        while f.readline() not in (b"\r\n", b"\n", b""):
            pass
        if not line.startswith("CONNECT"):
            return
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        t = leaf_ctx.wrap_socket(c, server_side=True)
        tf = t.makefile("rb")
        req = tf.readline().decode().split()
        hdrs, n = {}, 0
        while True:
            h = tf.readline().decode()
            if h in ("\r\n", "\n", ""):
                break
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
            if k.lower() == "content-length":
                n = int(v)
        body = tf.read(n) if n else None
        up = http.client.HTTPSConnection(HOST, timeout=30)
        fwd = {k: v for k, v in hdrs.items() if k.lower() not in ("connection", "accept-encoding")}
        up.request(req[0], req[1], body=body, headers=fwd)
        resp = up.getresponse()
        out = resp.read()
        if body and b"getSignedPolicy" in body and MODE["m"] != "pass":
            out = tamper(out)
        elif body and b"getSignedPolicy" in body:
            tamper(out)                             # record what the real server served
        t.sendall(f"HTTP/1.1 {resp.status} {resp.reason}\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(out)}\r\nConnection: close\r\n\r\n".encode() + out)
        t.close()
    except Exception as e:
        print("proxy:", e, file=sys.stderr)
    finally:
        c.close()


ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(8)
PROXY = f"http://127.0.0.1:{ls.getsockname()[1]}"
threading.Thread(target=lambda: [threading.Thread(target=handle, args=(ls.accept()[0],), daemon=True).start()
                                 for _ in iter(int, 1)], daemon=True).start()
box_env = dict(os.environ, HTTPS_PROXY=PROXY, https_proxy=PROXY, SSL_CERT_FILE=p("mitm-ca.pem"),
               NO_PROXY="", no_proxy="")


def pull(root=True):
    args = [BIN, "agent", "pull", "--url", API, "--machine", MID, "--key", p("machine.key"), "--out", OUT]
    if root:
        args += ["--root", ROOT]
    return sh(*args, env=box_env, ok=False)


def ca_file():
    try:
        return open(os.path.join(OUT, "trusted_user_ca_keys")).read()
    except OSError:
        return ""


# ── (a) v1 through the proxy untouched → lands on a real sshd ─────────────────
r = pull()
check(r.returncode == 0 and "pulled signed policy v" in r.stdout and "1 CA(s)" in r.stdout, f"(a) agent applied signed v1 [{(r.stdout + r.stderr).strip()[:160]}]")
check(ca1.split()[1] in ca_file(), "(a) CA1 written to trusted_user_ca_keys")
v1 = MODE["seen"][-1] if MODE["seen"] else None
V1 = json.loads(open(os.path.join(OUT, ".p3sig-policy-state.json")).read()).get("version") if r.returncode == 0 else None

sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", p("hostkey"))
sh("ssh-keygen", "-q", "-s", p("ca1"), "-I", "e2e", "-n", me, "-V", "+10m", p("user.pub"))
port = 22000 + secrets.randbelow(2000)
open(p("sshd_config"), "w").write(
    f"Port {port}\nListenAddress 127.0.0.1\nHostKey {p('hostkey')}\nPidFile {p('sshd.pid')}\n"
    f"UsePAM no\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
    f"AuthorizedKeysFile none\nTrustedUserCAKeys {os.path.join(OUT, 'trusted_user_ca_keys')}\n"
    f"RevokedKeys {os.path.join(OUT, 'revoked_keys')}\n")
procs.append(subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", p("sshd_config")],
                              stdout=subprocess.DEVNULL, stderr=open(p("sshd.log"), "w")))
time.sleep(1.5)


def ssh_as(cert):
    return sh("ssh", "-F", "/dev/null", "-p", str(port), "-i", p("user"), "-o", f"CertificateFile={p(cert)}",
              "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={p('kh')}",
              "-o", "BatchMode=yes", f"{me}@127.0.0.1", "echo", "in", ok=False).returncode == 0


shutil.copy(p("user-cert.pub"), p("ca1-cert.pub"))
check(ssh_as("ca1-cert.pub"), "(a) sshd accepts a cert from the device-signed CA")

# ── (b) injected CA via a trusted-but-rogue TLS cert → rejected, old CA kept ──
before = ca_file()
MODE["m"] = "inject"
r = pull()
check(r.returncode != 0 and "REJECTED" in r.stderr + r.stdout, f"(b) injected CA rejected [{(r.stderr + r.stdout).strip()[:160]}]")
check(ca_file() == before and "evil" not in ca_file(), "(b) trusted_user_ca_keys unchanged")
MODE["m"] = "unsigned"
r = pull()
check(r.returncode != 0 and ca_file() == before, "(b) stripped signature (unsigned response) refused, file unchanged")
MODE["m"] = "pass"

# ── (c) sign v2, apply it, then replay v1 ────────────────────────────────────
s2 = sign()
r = pull()
def applied_version():
    return json.loads(open(os.path.join(OUT, ".p3sig-policy-state.json")).read()).get("version")


V2 = applied_version() if r.returncode == 0 else None
check(s2.returncode == 0 and r.returncode == 0 and V1 is not None and V2 is not None and V2 > V1,
      f"(c) device-signed v2 applied (v{V2} > v{V1})")
MODE["m"], MODE["replay"] = "replay", v1
r = pull()
check(v1 is not None and r.returncode != 0 and "REJECTED" in r.stderr + r.stdout, f"(c) replayed v1 rejected [{(r.stderr + r.stdout).strip()[:160]}]")
MODE["m"] = "pass"

# ── (d) device signs v3, the owner revokes the device from the safe → v3 rejected ──
s3 = sign()
os.rename(p("root.safe"), p("root"))
rv = sh(BIN, "policy", "revoke", "--root-key", p("root"), "--device", p("device.pub"), env=env, ok=False)
os.rename(p("root"), p("root.safe"))
st_before = open(os.path.join(OUT, ".p3sig-policy-state.json")).read()
r = pull()
check(s3.returncode == 0 and rv.returncode == 0, "(d) v3 signed, then device revoked by the root")
check(r.returncode != 0 and "REJECTED" in r.stderr + r.stdout, f"(d) revoked device's v3 rejected [{(r.stderr + r.stdout).strip()[:160]}]")
check(json.loads(st_before).get("version") == V2 and applied_version() == V2 and ca_file() == before, "(d) box still on v2, CA file unchanged")
check(ssh_as("ca1-cert.pub"), "(d) sshd still accepts the CA1 cert (old config kept)")
s4 = sign()
check(s4.returncode != 0, "(d) server refuses a new policy from the revoked device")

for pr in procs:
    pr.terminate()
sh("kill", agent_pid, ok=False)
print(f"\naccount {email}  machine {MID}  root {ROOT}  dir {T}")
if not A.keep:
    shutil.rmtree(T, ignore_errors=True)
print(("FAILED: " + "; ".join(fails)) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
