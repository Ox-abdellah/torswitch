#!/usr/bin/env python3
"""TOR SWITCH v2.0 by Ox-abdellah: transparent Tor proxy toggle for Kali / Debian. Run `torswitch help`."""
import argparse
import fcntl
import json
import os
import pwd
import re
import select
import shutil
import socket
import subprocess
import sys
import termios
import textwrap
import threading
import time
import tty
import urllib.request

VERSION = "2.0"
BRAND = "Ox-abdellah"

TRANS_PORT = 9040
DNS_PORT = 5353
CONTROL_PORT = 9051
TORRC = "/etc/tor/torrc"
RESOLV = "/etc/resolv.conf"
STATE_DIR = "/var/lib/torswitch"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
RESOLV_STATE = os.path.join(STATE_DIR, "resolv.json")
LOCK_FILE = "/run/torswitch.lock"
INSTALL_PATH = "/usr/local/bin/torswitch"
SBIN_LINK = "/usr/sbin/torswitch"  # so that `sudo torswitch` works (sudo secure_path)
BEGIN = "## TORSWITCH BEGIN"
END = "## TORSWITCH END"
DISABLED = "#TORSWITCH-DISABLED# "
NAT_CHAIN = "TORSWITCH_NAT"
FLT_CHAIN = "TORSWITCH_FLT"
VIRT_NET = "10.192.0.0/10"
LAN_NETS = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]
COOKIE_PATHS = [
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
]
CHECK_URL = "https://check.torproject.org/api/ip"
WIDTH = 56

COUNTRIES = dict(p.split(":") for p in (
    "de:Germany fr:France nl:Netherlands us:USA gb:UK se:Sweden ch:Switzerland "
    "at:Austria ca:Canada fi:Finland no:Norway dk:Denmark ro:Romania pl:Poland "
    "cz:Czechia ru:Russia ua:Ukraine it:Italy es:Spain pt:Portugal ie:Ireland "
    "is:Iceland lu:Luxembourg be:Belgium bg:Bulgaria md:Moldova lt:Lithuania "
    "lv:Latvia ee:Estonia hu:Hungary sk:Slovakia rs:Serbia jp:Japan sg:Singapore "
    "hk:HongKong kr:Korea au:Australia br:Brazil in:India ir:Iran tr:Turkey "
    "il:Israel ma:Morocco za:SouthAfrica"
).split())

COLOR = False
QUIET = False      # True while on/off/recover run behind the progress bar
WARNINGS = []      # warnings collected while QUIET
_lock = None

# ================================================================ UI
def paint(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else str(s)

def green(s): return paint("32", s)
def red(s): return paint("31", s)
def yellow(s): return paint("33", s)
def cyan(s): return paint("36", s)
def bold(s): return paint("1", s)
def dim(s): return paint("2", s)

def info(m):
    if not QUIET:
        print(f"{cyan('[*]')} {m}")

def ok(m):
    if not QUIET:
        print(f"{green('[+]')} {m}")

def warn(m):
    if QUIET:
        WARNINGS.append(m)
    else:
        print(f"{yellow('[!]')} {m}")

def err(m):
    print(f"{red('[-]')} {m}", file=sys.stderr)

def header_lines():
    line = cyan("─" * WIDTH)
    return [line, bold(red(f"TOR SWITCH v{VERSION}".center(WIDTH))), bold(green(BRAND.center(WIDTH))), line]

def banner():
    if not QUIET:
        print("\n".join(header_lines()))

def check_row(flag_, label, detail=""):
    """flag_: True = pass, False = fail, None = info/warning."""
    mark = green("[✓]") if flag_ else (red("[✗]") if flag_ is False else yellow("[!]"))
    print(f"{mark} {label:<24}{detail}")

def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def fmt_time(sec):
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"

def flag(cc):
    if cc and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 97) for c in cc.lower())
    return "🌐"

def country(cc):
    if not cc:
        return "Unknown"
    return f"{flag(cc)} {COUNTRIES.get(cc.lower(), cc.upper())}"

class Progress:
    """Single-line progress bar used by on/off."""
    BAR = 30

    pct = 0

    def set(self, pct, text=""):
        self.pct = max(self.pct, min(100, int(pct)))
        n = self.BAR * self.pct // 100
        bar = "█" * n + "░" * (self.BAR - n)
        if sys.stdout.isatty():
            print(f"\r\033[K  [{green(bar)}] {self.pct:3d}%  {text}", end="", flush=True)

    def clear(self):
        if sys.stdout.isatty():
            print("\r\033[K", end="", flush=True)

# ================================================================ helpers
def run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr.strip()}")
    return r

def has(binary):
    return shutil.which(binary) is not None

def safe(fn, *a):
    """Run a step and keep going if it fails (important for off/recover)."""
    try:
        fn(*a)
    except Exception as e:
        warn(f"{fn.__name__}: {e}")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def save_state(**kw):
    os.makedirs(STATE_DIR, exist_ok=True)
    st = load_state()
    st.update(kw)
    with open(STATE_FILE, "w") as f:
        json.dump(st, f)

def acquire_lock():
    global _lock
    _lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        err("Another torswitch instance is running. Wait for it to finish.")
        sys.exit(1)

def os_name():
    try:
        with open("/etc/os-release") as f:
            return re.search(r'^PRETTY_NAME="?([^"\n]*)', f.read(), re.M).group(1)
    except (OSError, AttributeError):
        return "Unknown"

def tor_user():
    for name in ("debian-tor", "tor", "_tor"):
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    raise RuntimeError("Could not find the Tor system user (debian-tor / tor).")

# ================================================================ setup / self-healing
def ensure_deps():
    """Install missing packages automatically."""
    if not has("systemctl"):
        raise RuntimeError("systemd is required.")
    need = [p for p, present in (("tor", has("tor")),
                                 ("iptables", has("iptables") and has("ip6tables"))) if not present]
    if not need:
        return
    if not has("apt-get"):
        raise RuntimeError(f"Missing packages: {' '.join(need)}. Install them manually.")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    for step in (["install", "-y", *need], ["update"], ["install", "-y", *need]):
        r = subprocess.run(["apt-get", *step], capture_output=True, text=True, env=env)
        if step[0] == "install" and r.returncode == 0:
            return
    raise RuntimeError(f"Could not install: {' '.join(need)}")

def install_self():
    src = os.path.realpath(__file__)
    if os.path.realpath(INSTALL_PATH) != src:
        if os.path.lexists(INSTALL_PATH):
            os.remove(INSTALL_PATH)  # also removes a dangling symlink
        shutil.copy2(src, INSTALL_PATH)
        os.chmod(INSTALL_PATH, 0o755)
        ok(f"Installed to {INSTALL_PATH}")
    if os.path.realpath(SBIN_LINK) != os.path.realpath(INSTALL_PATH):
        if os.path.lexists(SBIN_LINK):
            os.remove(SBIN_LINK)
        os.symlink(INSTALL_PATH, SBIN_LINK)
        ok(f"Symlink created: {SBIN_LINK}")

def preflight(p):
    """Everything `on` needs before touching the network. Returns the Tor user."""
    p.set(4, "Checking system tools")
    p.set(8, "Checking dependencies")
    ensure_deps()
    p.set(12, "Checking Tor user")
    user = tor_user()
    p.set(16, "Cleaning previous session")
    stale_cleanup()
    p.set(19, "Checking Tor configuration")
    os.makedirs(os.path.dirname(TORRC), exist_ok=True)
    return user

def stale_cleanup():
    """Leftovers from an old session (e.g. after a reboot): resolv.conf points to Tor but no rules exist."""
    if os.path.exists(RESOLV_STATE) and not rules_active():
        warn("Found leftovers from an old session and cleaned them up.")
        safe(restore_resolv)
        safe(unconfigure_torrc)
        save_state(active=False, since=None)

# ================================================================ torrc
CONFLICT_RE = re.compile(r"^\s*(TransPort|DNSPort|ControlPort)\b", re.M)

def strip_block(text):
    return re.sub(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", "", text, flags=re.S)

def configure_torrc():
    os.makedirs(STATE_DIR, exist_ok=True)
    text = ""
    if os.path.exists(TORRC):
        orig = os.path.join(STATE_DIR, "torrc.orig")
        if not os.path.exists(orig):
            shutil.copy2(TORRC, orig)
        with open(TORRC) as f:
            text = strip_block(f.read())
    # self-heal: disable conflicting user settings (restored by `off`)
    text = CONFLICT_RE.sub(lambda m: DISABLED + m.group(0), text)
    block = "\n".join([BEGIN, f"VirtualAddrNetworkIPv4 {VIRT_NET}", "AutomapHostsOnResolve 1",
                       f"TransPort {TRANS_PORT}", f"DNSPort {DNS_PORT}", f"ControlPort {CONTROL_PORT}",
                       "CookieAuthentication 1", END]) + "\n"
    with open(TORRC, "w") as f:
        f.write(text.rstrip() + "\n\n" + block)

def unconfigure_torrc():
    if not os.path.exists(TORRC):
        return
    with open(TORRC) as f:
        text = f.read()
    if BEGIN in text or DISABLED in text:
        with open(TORRC, "w") as f:
            f.write(strip_block(text).replace(DISABLED, "").rstrip() + "\n")

def torrc_conflicts():
    try:
        with open(TORRC) as f:
            return CONFLICT_RE.findall(strip_block(f.read()))
    except OSError:
        return []

# ================================================================ resolv.conf
def resolv_is_ours():
    try:
        with open(RESOLV) as f:
            return "# torswitch" in f.read()
    except OSError:
        return False

def set_resolv():
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(RESOLV_STATE):
        with open(RESOLV) as f:
            state = {"link": os.readlink(RESOLV)} if os.path.islink(RESOLV) else {"content": f.read()}
        with open(RESOLV_STATE, "w") as f:
            json.dump(state, f)
    if os.path.lexists(RESOLV):
        os.remove(RESOLV)
    with open(RESOLV, "w") as f:
        f.write("# torswitch\nnameserver 127.0.0.1\n")

def restore_resolv():
    """Restore the original file; if NetworkManager already wrote a new one, keep it."""
    if not os.path.exists(RESOLV_STATE):
        return
    with open(RESOLV_STATE) as f:
        state = json.load(f)
    if resolv_is_ours() or not os.path.lexists(RESOLV):
        if os.path.lexists(RESOLV):
            os.remove(RESOLV)
        if "link" in state:
            os.symlink(state["link"], RESOLV)
        else:
            with open(RESOLV, "w") as f:
                f.write(state["content"])
    os.remove(RESOLV_STATE)

# ================================================================ tor service
def tor_is_active():
    return any(run(["systemctl", "is-active", "--quiet", u], check=False).returncode == 0
               for u in ("tor@default", "tor"))

def restart_tor():
    if run(["systemctl", "restart", "tor@default"], check=False).returncode != 0:
        run(["systemctl", "restart", "tor"])

def stop_tor():
    run(["systemctl", "stop", "tor@default"], check=False)
    run(["systemctl", "stop", "tor"], check=False)

# ================================================================ ControlPort
def _read_reply(s):
    buf = ""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            raise RuntimeError("Tor closed the control connection.")
        buf += chunk.decode(errors="replace")
        if buf.startswith("250"):
            if buf == "250 OK\r\n" or buf.endswith("\r\n250 OK\r\n"):
                return buf
        elif buf.endswith("\r\n"):
            return buf

def control(commands, timeout=10, strict=True):
    cookie = None
    for p in COOKIE_PATHS:
        if os.path.exists(p):
            with open(p, "rb") as f:
                cookie = f.read().hex()
            break
    if cookie is None:
        raise RuntimeError("Tor control cookie not found.")
    s = socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=timeout)
    try:
        out = []
        for c in [f"AUTHENTICATE {cookie}"] + commands:
            s.sendall((c + "\r\n").encode())
            r = _read_reply(s)
            if strict and not r.startswith("250"):
                raise RuntimeError(f"Tor control: {r.strip()}")
            out.append(r)
        return out[1:]
    finally:
        s.close()

def wait_bootstrap(on_progress=None, timeout=120):
    end, last = time.time() + timeout, -1
    while time.time() < end:
        try:
            m = re.search(r"PROGRESS=(\d+)", control(["GETINFO status/bootstrap-phase"])[0])
            prog = int(m.group(1)) if m else last
            if on_progress and prog != last:
                on_progress(prog)
            last = prog
            if prog >= 100:
                return
        except (OSError, RuntimeError):
            pass
        time.sleep(1)
    raise RuntimeError("Tor did not finish bootstrapping in time.")

# ================================================================ circuits
CIRC_RE = re.compile(r"^(\d+) BUILT (\S+) (.*)$")
HOP_RE = re.compile(r"\$?([0-9A-Fa-f]{40})(?:[~=](\S*))?")
RELAY_CACHE = {}  # fingerprint -> (ip, country code)

def parse_circuits(text):
    circs = []
    for line in text.splitlines():
        m = CIRC_RE.match(line)
        if not m or "PURPOSE=GENERAL" not in m.group(3):
            continue
        hops = []
        for h in m.group(2).split(","):
            hm = HOP_RE.match(h)
            if hm:
                hops.append({"fp": hm.group(1).upper(), "nick": hm.group(2) or "", "ip": None, "cc": None})
        if len(hops) >= 3:
            circs.append({"id": m.group(1), "hops": hops})
    return circs

def get_circuits():
    return parse_circuits(control(["GETINFO circuit-status"])[0])

def enrich(circs):
    """Add the IP and country of every relay (Tor's own GeoIP database, cached)."""
    todo = sorted({h["fp"] for c in circs for h in c["hops"]} - set(RELAY_CACHE))
    if todo:
        ips = {}
        for fp, r in zip(todo, control([f"GETINFO ns/id/{fp}" for fp in todo], strict=False)):
            m = re.search(r"^r \S+ \S+ \S+ \S+ \S+ (\d+\.\d+\.\d+\.\d+) ", r, re.M)
            if m:
                ips[fp] = m.group(1)
        uniq, ccs = sorted(set(ips.values())), {}
        for ip, r in zip(uniq, control([f"GETINFO ip-to-country/{ip}" for ip in uniq], strict=False) if uniq else []):
            m = re.search(r"=([a-z?]{2})", r)
            if m and m.group(1) != "??":
                ccs[ip] = m.group(1)
        RELAY_CACHE.update({fp: (ip, ccs.get(ip)) for fp, ip in ips.items()})
    for c in circs:
        for h in c["hops"]:
            h["ip"], h["cc"] = RELAY_CACHE.get(h["fp"], (None, None))

def pick_current(circs, stream_text, public_ip=None):
    """The circuit that carries the most active streams (fallback: exit IP match, then first)."""
    if not circs:
        return None
    counts = {}
    for m in re.finditer(r"^\d+ SUCCEEDED (\d+) ", stream_text, re.M):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    best = max(circs, key=lambda c: counts.get(c["id"], 0))
    if counts.get(best["id"], 0) > 0:
        return best
    for c in circs:
        if public_ip and c["hops"][-1]["ip"] == public_ip:
            return c
    return circs[0]

def ensure_circuits(timeout=30):
    """Wait for at least one ready circuit; if none appears, request a new identity once."""
    end, nudged = time.time() + timeout, False
    while time.time() < end:
        try:
            if get_circuits():
                return
            if not nudged and time.time() > end - timeout / 2:
                nudged = True
                control(["SIGNAL NEWNYM"])
        except (OSError, RuntimeError):
            pass
        time.sleep(2)

# ================================================================ firewall
def ipt(tool, *args):
    return run([tool, "-w", *args])

def hooked(tool, table, chain):
    if not has(tool):
        return False
    return run([tool, "-w", "-t", table, "-C", "OUTPUT", "-j", chain], check=False).returncode == 0

def rules_active():
    return hooked("iptables", "nat", NAT_CHAIN)

def backup_firewall():
    os.makedirs(STATE_DIR, exist_ok=True)
    for tool, name in (("iptables-save", "iptables.v4.bak"), ("ip6tables-save", "iptables.v6.bak")):
        if has(tool):
            r = run([tool], check=False)
            if r.returncode == 0:
                with open(os.path.join(STATE_DIR, name), "w") as f:
                    f.write(r.stdout)

def remove_chains():
    for tool in ("iptables", "ip6tables"):
        if not has(tool):
            continue
        for table, chain in (("nat", NAT_CHAIN), ("filter", FLT_CHAIN)):
            while run([tool, "-w", "-t", table, "-D", "OUTPUT", "-j", chain], check=False).returncode == 0:
                pass
            run([tool, "-w", "-t", table, "-F", chain], check=False)
            run([tool, "-w", "-t", table, "-X", chain], check=False)

def apply_rules(user):
    owner = ["-m", "owner", "--uid-owner", user]
    redirect = lambda port: ["-j", "REDIRECT", "--to-ports", str(port)]
    # NAT: redirect DNS and TCP to Tor
    ipt("iptables", "-t", "nat", "-N", NAT_CHAIN)
    nat = [owner + ["-j", "RETURN"],
           ["-p", "udp", "--dport", "53"] + redirect(DNS_PORT),
           ["-o", "lo", "-j", "RETURN"], ["-d", "127.0.0.0/8", "-j", "RETURN"],
           ["-d", VIRT_NET, "-p", "tcp"] + redirect(TRANS_PORT)]
    nat += [["-d", n, "-j", "RETURN"] for n in LAN_NETS]
    nat += [["-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN"] + redirect(TRANS_PORT)]
    for rule in nat:
        ipt("iptables", "-t", "nat", "-A", NAT_CHAIN, *rule)
    ipt("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", NAT_CHAIN)

    # Filter: kill switch. After REDIRECT the destination is 127.0.0.1 but the interface may stay wlan0.
    ipt("iptables", "-N", FLT_CHAIN)
    flt = [owner + ["-j", "ACCEPT"], ["-o", "lo", "-j", "ACCEPT"], ["-d", "127.0.0.0/8", "-j", "ACCEPT"]]
    flt += [["-d", n, "-j", "ACCEPT"] for n in LAN_NETS]
    flt += [["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"], ["-j", "REJECT"]]
    for rule in flt:
        ipt("iptables", "-A", FLT_CHAIN, *rule)
    ipt("iptables", "-I", "OUTPUT", "1", "-j", FLT_CHAIN)

    # IPv6: block everything (Tor cannot transparently proxy IPv6)
    if has("ip6tables"):
        if run(["ip6tables", "-w", "-N", FLT_CHAIN], check=False).returncode != 0:
            return warn("ip6tables failed: disable IPv6 (sysctl net.ipv6.conf.all.disable_ipv6=1).")
        for rule in (owner + ["-j", "ACCEPT"], ["-o", "lo", "-j", "ACCEPT"],
                     ["-d", "::1/128", "-j", "ACCEPT"], ["-j", "REJECT"]):
            ipt("ip6tables", "-A", FLT_CHAIN, *rule)
        ipt("ip6tables", "-I", "OUTPUT", "1", "-j", FLT_CHAIN)

# ================================================================ verify
def check_ip(retries=3, timeout=20):
    req = urllib.request.Request(CHECK_URL, headers={"User-Agent": "torswitch"})
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(2)

def verify_tor():
    try:
        data = check_ip()
    except Exception:
        if get_circuits():  # cannot reach the check site, but Tor itself has circuits
            return
        raise RuntimeError("Could not verify the Tor connection.")
    if not data.get("IsTor"):
        raise RuntimeError(f"Exit IP {data.get('IP')} is not a Tor IP.")

def request_newnym():
    wait = 10 - (time.time() - load_state().get("last_newnym", 0))
    if wait > 0:  # Tor limits identity changes to about once per 10 seconds
        time.sleep(wait + 1)
    control(["SIGNAL NEWNYM"])
    save_state(last_newnym=time.time())

# ================================================================ commands: on / off / recover
def rollback():
    for fn in (remove_chains, restore_resolv, unconfigure_torrc, stop_tor):
        safe(fn)
    save_state(active=False, since=None)

def finish(message):
    global QUIET
    QUIET = False
    print()
    print(green(f"[✓] {message}"))
    for w in WARNINGS:
        print(f"{yellow('[!]')} {w}")

def cmd_on():
    global QUIET
    QUIET = True
    p = Progress()
    try:
        p.set(2, "Preflight checks")
        user = preflight(p)
        p.set(22, "Creating backups")
        backup_firewall()
        remove_chains()
        p.set(26, "Configuring Tor")
        configure_torrc()
        p.set(30, "Starting Tor")
        restart_tor()
        wait_bootstrap(lambda x: p.set(30 + x * 0.4, "Connecting to the Tor network"))
        p.set(72, "Protecting DNS")
        set_resolv()
        p.set(80, "Applying firewall rules")
        apply_rules(user)
        p.set(88, "Building circuits")
        ensure_circuits()
        p.set(94, "Verifying Tor connection")
        verify_tor()
    except (Exception, KeyboardInterrupt) as e:
        p.clear()
        rollback()
        QUIET = False
        print(red(f"[✗] TOR SWITCH FAILED: {e or 'interrupted'}"), file=sys.stderr)
        print(dim("    Everything was rolled back."), file=sys.stderr)
        sys.exit(1)
    save_state(active=True, since=int(time.time()))
    p.set(100, "Done")
    finish("TOR SWITCH ENABLED")

def cmd_off():
    global QUIET
    QUIET = True
    p = Progress()
    p.set(5, "Preparing")
    for fn, pct, text in ((remove_chains, 20, "Removing firewall rules"),
                          (restore_resolv, 45, "Restoring DNS"),
                          (unconfigure_torrc, 65, "Restoring Tor configuration"),
                          (stop_tor, 85, "Stopping Tor")):
        p.set(pct, text)
        safe(fn)
    save_state(active=False, since=None)
    p.set(100, "Done")
    finish("TOR SWITCH DISABLED")

def cmd_recover():
    banner()
    warn("Recovery mode: restoring everything...")
    for fn in (remove_chains, restore_resolv, unconfigure_torrc, stop_tor):
        safe(fn)
    if resolv_is_ours():  # no backup available: let NetworkManager rewrite it
        run(["systemctl", "restart", "NetworkManager"], check=False)
        time.sleep(2)
        if resolv_is_ours():
            with open(RESOLV, "w") as f:
                f.write("nameserver 1.1.1.1\nnameserver 9.9.9.9\n")
            warn("Wrote a temporary DNS (1.1.1.1).")
    save_state(active=False, since=None)
    ok("Done. Internet should work again. If not, reboot (rules are not persistent).")

def cmd_newnym():
    banner()
    info("Requesting a new identity...")
    try:
        request_newnym()
        time.sleep(2)
        ok(f"New IP: {check_ip(retries=2, timeout=15).get('IP')}")
    except Exception as e:
        err(f"Failed: {e} (is Tor running? try: sudo torswitch on)")
        sys.exit(1)

def cmd_install():
    banner()
    info("Checking dependencies...")
    try:
        ensure_deps()
    except RuntimeError as e:
        err(str(e))
        sys.exit(1)
    install_self()
    save_state(setup_done=True, version=VERSION)
    ok("Setup complete. Run: sudo torswitch on")

def cmd_doctor():
    banner()
    problems = 0
    fix = "Run: sudo torswitch on"

    def chk(flag_, label, detail="", hint=""):
        nonlocal problems
        check_row(flag_, label, detail)
        if flag_ is False:
            problems += 1
            if hint:
                print(f"      → {hint}")

    chk(os.geteuid() == 0, "Root")
    check_row(True, "Operating System", os_name())
    for b in ("tor", "iptables", "ip6tables", "systemctl"):
        chk(has(b), b, hint=fix + " (installs missing packages)")
    up = tor_is_active()
    check_row(True if up else None, "Tor service", "running" if up else "stopped (normal when off)")
    if up:
        try:
            control(["GETINFO version"])
            chk(True, "ControlPort + cookie")
        except Exception as e:
            chk(False, "ControlPort + cookie", hint=str(e)[:60])
    conf = torrc_conflicts()
    chk(not conf, "torrc conflicts", ",".join(conf), fix + " (fixes it automatically)")
    if rules_active():
        chk(up, "Tor with active rules", hint="Run: sudo torswitch recover")
        chk(resolv_is_ours(), "DNS -> Tor", hint=fix)
        chk(hooked("iptables", "filter", FLT_CHAIN), "Kill switch")
        chk(hooked("ip6tables", "filter", FLT_CHAIN) or not has("ip6tables"), "IPv6 blocked")
    else:
        chk(not os.path.exists(RESOLV_STATE) and not resolv_is_ours(), "Leftovers",
            hint="Run: sudo torswitch recover")
    print()
    print(green("  Result: SYSTEM READY") if not problems
          else red(f"  Result: {problems} problem(s)") + "  ->  sudo torswitch recover")

# ================================================================ live dashboard
_slow = {"t": 0.0, "data": {}}
_id_lock = threading.Lock()

def slow_checks():
    """Service / firewall state, refreshed every 3 seconds (spawns processes)."""
    if time.time() - _slow["t"] >= 3:
        _slow["t"] = time.time()
        _slow["data"] = {"tor": tor_is_active(), "rules": rules_active(), "dns": resolv_is_ours(),
                         "kill": hooked("iptables", "filter", FLT_CHAIN),
                         "ipv6": hooked("ip6tables", "filter", FLT_CHAIN)}
    return _slow["data"]

class IPWatcher(threading.Thread):
    """Looks up the public IP in the background so the dashboard never blocks."""

    def __init__(self):
        super().__init__(daemon=True)
        self.ip = None
        self.is_tor = None
        self._kick = threading.Event()
        self._delay = 0

    def kick(self, delay=3):
        self._delay = delay
        self.ip = None
        self._kick.set()

    def fetch(self):
        try:
            data = check_ip(retries=1, timeout=10)
            self.ip, self.is_tor = data.get("IP"), bool(data.get("IsTor"))
        except Exception:
            pass

    def run(self):
        while True:
            time.sleep(self._delay)
            self._delay = 0
            self.fetch()
            self._kick.wait(20)
            self._kick.clear()

def snapshot(watcher):
    d = dict(slow_checks())
    d["protected"] = bool(d["tor"] and d["rules"])
    since = load_state().get("since")
    d["uptime"] = int(time.time() - since) if d["protected"] and since else None
    d.update(ip=watcher.ip, is_tor=watcher.is_tor, circs=[], current=None, read=None, written=None)
    if d["tor"]:
        try:
            rep = control(["GETINFO circuit-status", "GETINFO stream-status",
                           "GETINFO traffic/read", "GETINFO traffic/written"], strict=False)
            circs = parse_circuits(rep[0])
            enrich(circs)
            d["circs"], d["current"] = circs, pick_current(circs, rep[1], watcher.ip)
            m = re.search(r"=(\d+)", rep[2])
            d["read"] = int(m.group(1)) if m else None
            m = re.search(r"=(\d+)", rep[3])
            d["written"] = int(m.group(1)) if m else None
        except (OSError, RuntimeError):
            pass
    return d

def render(d, notice="", menu=True):
    L = header_lines() + [""]

    def r(label, value):
        L.append(f"{label:<12} : {value}")

    def mark(flag_, yes, no):
        return green("✓ " + yes) if flag_ else dim("✗ " + no)

    r("Status", green("● PROTECTED") if d["protected"] else red("○ NOT PROTECTED"))
    if d["ip"]:
        r("Public IP", d["ip"] + ("" if d["is_tor"] else yellow("  (real IP, not Tor)")))
    else:
        r("Public IP", dim("checking..."))
    cur = d["current"]
    r("Exit Country", country(cur["hops"][-1]["cc"]) if cur else dim("-"))
    r("Tor Circuits", str(len(d["circs"])) if d["tor"] else dim("-"))
    if cur:
        L += ["", "Current Circuit"]
        for i, h in enumerate(cur["hops"]):
            branch = "└──" if i == len(cur["hops"]) - 1 else "├──"
            name = country(h["cc"]) if h["cc"] else (h["nick"] or "?")
            L.append(f"{branch} {name:<18} {h['ip'] or '?'}")
    L.append("")
    r("DNS", mark(d["dns"], "Protected", "Not protected"))
    r("IPv6", mark(d["ipv6"], "Blocked", "Not blocked"))
    r("Kill Switch", mark(d["kill"], "Enabled", "Disabled"))
    if d["read"] is not None:
        r("Traffic", f"↑ {human(d['written'] or 0)}   ↓ {human(d['read'])}")
    if d["uptime"] is not None:
        r("Uptime", fmt_time(d["uptime"]))
    if menu:
        L += ["", f"{cyan('[1]')} Change Identity", f"{cyan('[2]')} Help",
              f"{cyan('[3]')} Recover", f"{cyan('[0]')} Exit"]
        if not d["protected"]:
            L += ["", dim("Tor is off. Run: sudo torswitch on")]
        if notice:
            L += ["", yellow(notice)]
    return L

def read_key(fd, timeout):
    if select.select([fd], [], [], timeout)[0]:
        return os.read(fd, 1).decode(errors="ignore").lower()
    return ""

def identity_job(watcher, say):
    if not _id_lock.acquire(False):
        return
    try:
        say("Requesting a new identity...", 20)
        request_newnym()
        watcher.kick()
        say("New identity requested.", 4)
    except Exception as e:
        say(f"Identity change failed: {e}", 6)
    finally:
        _id_lock.release()

def help_screen(fd):
    sys.stdout.write("\033[2J\033[H")
    print_help()
    print("  Press any key to go back")
    sys.stdout.flush()
    select.select([fd], [], [])
    os.read(fd, 16)

def dashboard():
    global QUIET
    QUIET = True
    stale_cleanup()
    QUIET = False
    watcher = IPWatcher()
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        watcher.fetch()
        print("\n".join(render(snapshot(watcher), menu=False)))
        return
    watcher.start()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    ui = {"text": "", "until": 0.0}
    confirm_until = 0.0

    def say(text, secs=5):
        ui["text"], ui["until"] = text, time.time() + secs

    try:
        tty.setcbreak(fd)
        sys.stdout.write("\033[?25l\033[2J")
        while True:
            now = time.time()
            frame = render(snapshot(watcher), ui["text"] if now < ui["until"] else "")
            sys.stdout.write("\033[H" + "".join(line + "\033[K\n" for line in frame) + "\033[J")
            sys.stdout.flush()
            key = read_key(fd, 1.0)
            if key in ("0", "q"):
                break
            if key == "1":
                threading.Thread(target=identity_job, args=(watcher, say), daemon=True).start()
            elif key == "2":
                help_screen(fd)
                sys.stdout.write("\033[2J")
            elif key == "3":
                if now < confirm_until:
                    confirm_until = 0.0
                    QUIET = True
                    try:
                        cmd_recover()
                    finally:
                        QUIET = False
                    _slow["t"] = 0.0
                    watcher.kick(1)
                    say("Recovered: Tor stopped and the network was restored.", 6)
                else:
                    confirm_until = now + 5
                    say("Press [3] again to confirm: this stops Tor and restores the network.", 5)
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()

# ================================================================ help
HELP_COMMANDS = [
    ("on", "Start Tor and route ALL traffic (TCP + DNS) through it. Fixes missing packages and settings automatically. Rolls back if anything fails."),
    ("off", "Turn everything off and restore the normal network. Your own firewall rules are never touched."),
    ("status", "Open the live dashboard: protection state, exit IP and country, current circuit, DNS, kill switch, traffic."),
    ("newnym", "Request a new Tor identity (new circuits and exit IP) from the command line."),
    ("doctor", "Run a full health check and print a fix hint next to every problem."),
    ("recover", "Emergency mode: remove all torswitch rules, restore DNS and torrc, stop Tor. Use it if the internet stops working."),
    ("install", "Register the torswitch command in /usr/local/bin. Run it again after downloading a newer version to upgrade."),
    ("help", "Show this help."),
    ("(none)", "Same as status."),
]
HELP_ON_STEPS = [
    ("1. Preflight", "Check root, tor, iptables, ip6tables and systemd. Install anything missing automatically."),
    ("2. Backup", "Save the firewall rules, torrc and resolv.conf to /var/lib/torswitch/."),
    ("3. Configure Tor", "Add a managed block to /etc/tor/torrc (TransPort 9040, DNSPort 5353, ControlPort 9051). Conflicting settings are disabled and restored by off."),
    ("4. Start Tor", "Start the Tor service and wait for 100% bootstrap before touching the network."),
    ("5. DNS", "Point /etc/resolv.conf to 127.0.0.1 so every DNS query goes through Tor."),
    ("6. Firewall", "Redirect TCP + DNS to Tor, enable the kill switch and block IPv6."),
    ("7. Verify", "Check that your exit IP is a Tor IP. If not, everything is rolled back."),
]
HELP_KEYS = [
    ("1", "Change Identity: request a new Tor identity (new circuit and exit IP)."),
    ("2", "Help: show this screen."),
    ("3", "Recover: stop Tor and restore the network. Press 3 twice to confirm."),
    ("0", "Exit: close the dashboard. Tor keeps running."),
]
HELP_FIELDS = [
    ("Status", "PROTECTED = Tor is running AND the traffic rules are active."),
    ("Public IP", "The IP the internet sees. It should be a Tor exit IP."),
    ("Exit Country", "Country of the exit relay of the current circuit."),
    ("Tor Circuits", "Number of ready Tor circuits (managed automatically by Tor)."),
    ("Current Circuit", "The circuit carrying your traffic: entry (guard), middle and exit relays with country and IP."),
    ("DNS", "Protected = DNS queries go through Tor (no DNS leaks)."),
    ("IPv6", "Blocked = IPv6 is rejected because Tor cannot proxy it."),
    ("Kill Switch", "Enabled = any traffic that does not go through Tor is blocked."),
    ("Traffic", "Bytes sent and received by Tor since it started."),
    ("Uptime", "Time since `on` finished."),
]
HELP_SAFETY = [
    ("Own chains", "Only TORSWITCH_* iptables chains are used. Your rules are never flushed."),
    ("Order", "Firewall rules are applied only after Tor reaches 100% bootstrap."),
    ("Backups", "Saved in /var/lib/torswitch/ before any change."),
    ("SSH", "An existing SSH session is cut while Tor is on (kill switch)."),
    ("Reboot", "Rules are not persistent. If DNS is broken after a reboot, run: sudo torswitch recover"),
    ("Anonymity", "Tor hides your IP, not your identity. Logging in to personal accounts still identifies you. Use Tor Browser for sensitive browsing."),
]
def table(headers, rows, widths, indent="  "):
    def sep(l, m, r):
        return indent + l + m.join("─" * (w + 2) for w in widths) + r

    def line(cells, styles):
        wrapped = [textwrap.wrap(c, w) or [""] for c, w in zip(cells, widths)]
        for i in range(max(len(c) for c in wrapped)):
            parts = [" " + st((c[i] if i < len(c) else "").ljust(w)) + " "
                     for c, w, st in zip(wrapped, widths, styles)]
            print(indent + "│" + "│".join(parts) + "│")

    print(sep("┌", "┬", "┐"))
    line(headers, [lambda t: bold(cyan(t))] * len(widths))
    print(sep("├", "┼", "┤"))
    for r in rows:
        line(r, [lambda t: bold(green(t))] + [lambda t: t] * (len(widths) - 1))
    print(sep("└", "┴", "┘"))

def print_help():
    print("\n".join(header_lines()))
    print("\n  Routes ALL your traffic through Tor with one command and")
    print("  restores everything with another (transparent proxy).")
    print(f"\n  Usage: {bold('sudo torswitch [command]')}\n")
    for title, headers, rows, widths in (
        ("COMMANDS", ("Command", "Description"), HELP_COMMANDS, (10, 56)),
        ("WHAT `on` DOES", ("Step", "What happens"), HELP_ON_STEPS, (16, 50)),
        ("DASHBOARD KEYS", ("Key", "Action"), HELP_KEYS, (6, 60)),
        ("DASHBOARD FIELDS", ("Field", "Meaning"), HELP_FIELDS, (16, 50)),
        ("SAFETY AND NOTES", ("Topic", "Details"), HELP_SAFETY, (12, 54)),
    ):
        print(bold(f"  {title}"))
        table(headers, rows, widths)
        print()

# ================================================================ main
def main():
    global COLOR
    p = argparse.ArgumentParser(prog="torswitch", add_help=False)
    p.add_argument("command", nargs="?", metavar="command",
                   choices=["on", "off", "status", "newnym", "doctor", "recover", "install", "help"])
    p.add_argument("-V", "--version", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    args = p.parse_args()
    cmd = args.command
    COLOR = sys.stdout.isatty()

    if args.version:
        print(f"TorSwitch v{VERSION} by {BRAND}")
        return
    if args.help or cmd == "help":
        print_help()
        return
    if os.geteuid() != 0:
        err("This tool must be run with sudo.")
        sys.exit(1)
    acquire_lock()

    actions = {"on": cmd_on, "off": cmd_off, "status": dashboard, "newnym": cmd_newnym,
               "doctor": cmd_doctor, "recover": cmd_recover, "install": cmd_install, None: dashboard}
    try:
        actions[cmd]()
    except KeyboardInterrupt:
        print()
        err("Interrupted. If the internet stopped working run: sudo torswitch recover")
        sys.exit(130)

if __name__ == "__main__":
    main()
