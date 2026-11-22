#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chrome 翻译一键修复工具
=======================
通过修改 hosts 让 translate.googleapis.com 指向可用的 Google IP，恢复 Chrome 内置翻译。

功能
  * 一键修复（默认 IPv4+IPv6 都修复）：先测本地库；首次使用或本地库失效时先做约 1 分钟的快速扫描建库，
    再复测延迟并写入 hosts；快速扫描没找到才进入耗时更长的深度扫描
  * 扫描：在 Google 地址段内随机抽样探测（真实 TLS + 证书校验 + 翻译接口请求），支持 IPv4 / IPv6
  * 同时写入 IPv4 与 IPv6（默认），也可只用其中一种；支持 NAT64 网关通道（IPv4 被限制时仍可用 IPv6 走通）
  * 默认同时映射 translate.googleapis.com / translate.google.com / translate-pa.googleapis.com / jnn-pa.googleapis.com
  * 修改前自动备份 hosts，随时可一键还原；只改动自己的标记区块，不碰你其它的 hosts 内容

用法
  图形界面：   python gtfix.py                （Windows 会自动请求管理员权限）
  命令行：     python gtfix.py --fix | --scan | --test | --status | --restore
               python gtfix.py --set 2404:6800:4008:c00::5f 142.250.196.138
  共享库：     python gtfix.py --shared-repo 用户名/仓库名 --fix   （先用共享的可用 IP 试，失效再扫描）
               python gtfix.py --share / --export   （分享 / 导出本机验证过的 IP）
  常用选项：   --ipv4 / --ipv6 只用某个协议；--no-scan 不自动扫描；--cidr 指定自定义扫描网段（可多次）
               --deep 深度扫描；--offline 不联网扩展；自定义范围也可写入 gtfix_ranges.txt
macOS / Linux 需要：sudo python3 gtfix.py --fix
"""
import argparse
import ctypes
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from urllib.parse import quote
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "translate.googleapis.com"
SCAN_STATS = Counter()   # {(v4/v6, 失败原因): 次数}，用于判断直连 IPv4 是否已整体失效
SCAN_DEAD4 = False
SCAN_ALIVE = Counter()   # {v4/v6: TCP 443 可连通的数量}
BEGIN = "# >>> gtfix begin (Chrome translate fix) >>>"
END = "# <<< gtfix end <<<"
DISABLED = "#[gtfix-disabled] "
IS_WIN = os.name == "nt"

# 新版 Chrome 翻译会用到的域名（参考 2026 年社区方案）。默认全部映射到同一个 IP。
MANAGED_HOSTS = [HOST, "translate.google.com", "translate-pa.googleapis.com", "jnn-pa.googleapis.com"]
ACTIVE_HOSTS = list(MANAGED_HOSTS)


def set_hosts_mode(all_hosts=True):
    global ACTIVE_HOSTS
    ACTIVE_HOSTS = list(MANAGED_HOSTS) if all_hosts else [HOST]


# 公共 NAT64 网关前缀（来源 nat64.xyz）。NAT64 地址 = 前缀 + Google 的 IPv4：
# 流量走 IPv6 到欧洲网关，再由网关以 IPv4 访问 Google（TLS 仍是与 Google 端到端，证书照常校验）。
NAT64_PREFIXES = [
    "2001:67c:2960:6464::",      # level66.network（社区文章里使用的）
    "2a00:1098:2b::",            # Kasper Dupont (nat64.net)
    "2a00:1098:2c:1::",
    "2a01:4f8:c2c:123f:64::",
    "2a01:4f9:c010:3f02:64::",
    "2001:67c:2b0:db32:0:1::",   # Trex
    "2a03:7900:6446::",          # Tuxis
]
# ---- 共享可用 IP 库（你自己 GitHub 仓库里的 ips.txt）----
# 发布到 GitHub 后，把 SHARED_REPO 改成 "你的用户名/仓库名"（也可用环境变量 GTFIX_SHARED_REPO 或 --shared-repo）。
# 留空则不启用共享功能。共享库里的 IP 是“不可信数据”：每个 IP 仍须在本机通过证书与接口探测才会被采用。
SHARED_REPO = ""
SHARED_BRANCH = "main"
SHARED_FILE = "ips.txt"

NAT64_SEED_V4 = "216.239.32.73"  # 社区文章里 NAT64 方案使用的 Google IPv4

if IS_WIN:
    HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
else:
    HOSTS = "/etc/hosts"

# ---- 预制 IP（仅为示例，使用前一定会实测；失效后用扫描功能）-------------------
# ---- 内置 IP 库：取自开源项目 hcfyapp/google-translate-cn-ip 收集的可用 IP（含社区补充）----
# 注意：这些是历史收集的 IP，会随时间失效；规律是绝大多数以 .90 结尾（googleapis 前端）。
LIB_IPS = list(dict.fromkeys("""142.250.4.90 172.253.114.90 172.217.203.90 172.253.112.90 142.250.9.90 172.253.116.90 142.250.97.90 142.250.30.90
142.250.111.90 172.217.215.90 142.250.11.90 142.251.9.90 108.177.122.90 142.250.96.90 142.250.100.90 142.250.110.90
172.217.214.90 172.217.222.90 142.250.31.90 142.250.126.90 142.250.10.90 172.217.195.90 172.253.115.90 142.251.5.90
142.250.136.90 142.250.12.90 142.250.101.90 172.217.192.90 142.250.0.90 142.250.107.90 172.217.204.90 142.250.28.90
142.250.125.90 172.253.124.90 142.250.8.90 142.250.128.90 142.250.112.90 142.250.27.90 142.250.105.90 172.253.126.90
172.253.123.90 172.253.122.90 172.253.62.90 142.250.98.90 142.250.185.238 142.251.116.101 216.58.214.14 142.250.189.206
216.58.209.174 142.250.203.142 142.250.218.14 142.251.10.138 142.251.40.174 142.250.185.174 172.217.16.46 172.217.0.46
172.217.31.142 216.58.220.142 172.217.13.142 172.253.113.90 108.177.97.100 108.177.111.90 108.177.125.186 108.177.126.90
108.177.127.90 142.250.1.90 142.250.13.90 142.250.99.90 142.250.102.90 142.250.103.90 142.250.113.90 142.250.114.90
142.250.115.90 142.250.123.90 142.250.138.90 142.250.141.90 142.250.142.90 142.250.145.90 142.250.152.90 142.250.153.90
142.250.157.90 142.250.157.183 142.250.157.184 142.250.157.186 142.250.158.90 142.250.159.90 142.251.1.90 142.251.2.90
142.251.4.90 142.251.6.90 142.251.8.90 142.251.10.90 142.251.12.90 142.251.15.90 142.251.16.90 142.251.18.90
142.251.107.90 142.251.111.90 142.251.112.90 142.251.116.90 142.251.117.90 142.251.120.90 142.251.160.90 142.251.161.90
142.251.162.90 142.251.163.90 142.251.166.90 172.253.58.90 172.253.63.90 172.253.117.90 172.253.118.90 172.253.119.90
172.253.125.90 172.253.127.90 216.58.227.65 216.58.227.66 216.58.227.67 74.125.137.90 74.125.193.186 74.125.196.113
172.217.215.90 108.177.122.90""".split()))
PRESET_V4 = LIB_IPS + ["183.56.143.147"]   # 最后一个来自 2026 年社区文章，需通过证书校验才会被采用
PRESET_V6 = []          # IPv6 没有稳定的公开库，靠扫描获得
# 在线 IP 库镜像（任一成功即可）
LIB_URLS = [
    "https://unpkg.com/@hcfy/google-translate-ip/ips.txt",
    "https://cdn.jsdelivr.net/npm/@hcfy/google-translate-ip/ips.txt",
    "https://raw.githubusercontent.com/hcfyapp/google-translate-cn-ip/master/packages/google-translate-ip/ips.txt",
    "https://cdn.jsdelivr.net/gh/hcfyapp/google-translate-cn-ip@master/packages/google-translate-ip/ips.txt",
]
# ---- 扫描用的 Google 地址段 --------------------------------------------------
V4_RANGES = [
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16",
    "108.177.0.0/17", "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17",
    "64.233.160.0/19", "192.178.0.0/15",
]

BEGIN_B, END_B, DIS_B, HOST_B = BEGIN.encode(), END.encode(), DISABLED.encode(), HOST.encode()
MANAGED_B = {h.encode() for h in MANAGED_HOSTS}
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0


# =============================================================================
# 一、hosts 读写（按字节处理，保持原有编码与换行符）
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0 if IS_WIN else os.geteuid() == 0
    except Exception:
        return False


def _eol(raw):
    if b"\r\n" in raw:
        return b"\r\n"
    if b"\n" in raw:
        return b"\n"
    return b"\r\n" if IS_WIN else b"\n"


def _is_host_line(line):
    s = line.strip()
    if not s or s.startswith(b"#"):
        return False
    parts = s.split(b"#")[0].split()
    return len(parts) >= 2 and any(p.lower() in MANAGED_B for p in parts[1:])


def _strip_block(raw):
    """去掉本工具的区块，恢复被本工具注释掉的手写行。返回 (行列表, 换行符)。"""
    out, inside = [], False
    for line in raw.splitlines():
        s = line.strip()
        if s == BEGIN_B:
            inside = True
            continue
        if s == END_B:
            inside = False
            continue
        if inside:
            continue
        if line.startswith(DIS_B):
            line = line[len(DIS_B):]
        out.append(line)
    return out, _eol(raw)


def block_ips(path=None):
    """读取 hosts 里本工具当前写入的 IP。"""
    raw = open(path or HOSTS, "rb").read()
    ips, inside = [], False
    for line in raw.splitlines():
        s = line.strip()
        if s == BEGIN_B:
            inside = True
        elif s == END_B:
            inside = False
        elif inside and s and not s.startswith(b"#"):
            ips.append(s.split()[0].decode())
    return list(dict.fromkeys(ips))


def _write(path, data):
    if IS_WIN:  # 清除只读属性
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            pass
    with open(path, "wb") as f:
        f.write(data)


def _backup(path):
    bak = path + ".gtfix.bak"
    if not os.path.exists(bak):
        shutil.copyfile(path, bak)


def apply_ips(ips, path=None):
    path = path or HOSTS
    ips = [str(ipaddress.ip_address(i.strip())) for i in ips]
    raw = open(path, "rb").read()
    _backup(path)
    lines, eol = _strip_block(raw)
    lines = [DIS_B + l if _is_host_line(l) else l for l in lines]  # 与我们冲突的手写行先注释
    while lines and not lines[-1].strip():
        lines.pop()
    block = [BEGIN_B] + [f"{ip} {h}".encode() for ip in ips for h in ACTIVE_HOSTS] + [END_B]
    _write(path, eol.join(lines + [b""] + block) + eol)


def restore_hosts(path=None):
    path = path or HOSTS
    raw = open(path, "rb").read()
    lines, eol = _strip_block(raw)
    while lines and not lines[-1].strip():
        lines.pop()
    _write(path, eol.join(lines) + eol)


def flush_dns():
    if IS_WIN:
        cmds = [["ipconfig", "/flushdns"]]
    elif sys.platform == "darwin":
        cmds = [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]
    else:
        cmds = [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]]
    for c in cmds:
        try:
            subprocess.run(c, capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass


# =============================================================================
# 二、探测与扫描
# =============================================================================
V6_TEST_TARGETS = [
    ("2402:f000:1:400::2", "清华TUNA(境内)"),
    ("2400:3200::1", "阿里DNS(境内)"),
    ("2606:4700:4700::1111", "Cloudflare(境外)"),
    ("2001:4860:4860::8888", "GoogleDNS(境外)"),
]
_V6_CACHE = {"t": 0.0, "ok": False, "res": []}


def has_ipv6(force=False):
    """真实检测 IPv6 外网连通：有路由，且至少一个测试目标的 TCP 443 能连上（结果缓存 2 分钟）。"""
    if not force and time.time() - _V6_CACHE["t"] < 120:
        return _V6_CACHE["ok"]
    res = []
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.connect(("2001:4860:4860::8888", 53))      # UDP connect 不发包，只检查路由
        s6.close()
        with ThreadPoolExecutor(4) as ex:
            oks = list(ex.map(lambda t: tcp_alive(t[0], 3.0), V6_TEST_TARGETS))
        res = [(name, ok) for (_, name), ok in zip(V6_TEST_TARGETS, oks)]
    except Exception:
        res = []
    _V6_CACHE.update(t=time.time(), ok=any(ok for _, ok in res), res=res)
    return _V6_CACHE["ok"]


def ipv6_report(log=print):
    res = _V6_CACHE["res"]
    if not _V6_CACHE["t"]:
        return
    if not res:
        log("IPv6 连通性：本机没有 IPv6 路由。")
        return
    log("IPv6 连通性检测：" + "、".join(f"{n}{'✔' if ok else '✘'}" for n, ok in res))
    dom = any(ok for n, ok in res if "境内" in n)
    abroad = any(ok for n, ok in res if "境外" in n)
    if not dom and not abroad:
        log("  → 本机 IPv6 到不了互联网（可能只有局域网/链路本地地址）。")
    elif dom and not abroad:
        log("  → 只有境内 IPv6 能通，境外 IPv6 不通：Google / NAT64 的 IPv6 候选大概率也不通。"
            "IPv4 已可用时可以忽略 IPv6。")


PROBE_PATHS = [
    "/translate_a/l?client=chrome&hl=en",
    "/translate_a/single?client=gtx&sl=en&tl=zh-CN&dt=t&q=hello",
]


def _http_get(ip, path, host=HOST, conn_timeout=3.0, tls_timeout=5.0, want_body=False):
    """直连 ip:443，SNI=host 并校验证书，GET path。返回 (状态码, 响应头dict, 正文bytes, 耗时ms)。网络异常向上抛。"""
    s = None
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(conn_timeout)
        s.connect((ip, 443))
        s.settimeout(tls_timeout)
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        buf, limit = b"", (8192 if want_body else 2048)
        while len(buf) < limit:
            c = s.recv(4096)
            if not c:
                break
            buf += c
            if not want_body and b"\r\n" in buf:
                break
        ms = (time.perf_counter() - t0) * 1000
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", lines[0] if lines else b"")
        code = int(m.group(1)) if m else 0
        hdr = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            hdr[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
        return code, hdr, body, ms
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_ex(ip, conn_timeout=4.0, tls_timeout=9.0):
    """
    探测 IP 是否能正常提供翻译接口：TLS 证书必须通过校验，且接口返回 HTTP 200 或 429 才算可用。
      200 = 正常；429 = 这是真正的 Google 翻译前端，只是对探测请求限流（实测写入 hosts 后翻译可用）。
      404 等 = 连到的是不提供翻译接口的节点（例如境内的 Google 节点），写进 hosts 也没用，不算可用。
    返回 (耗时ms 或 None, 原因)。
    """
    last = "无HTTP响应"
    for path in PROBE_PATHS:
        try:
            code, _, _, ms = _http_get(ip, path, conn_timeout=conn_timeout, tls_timeout=tls_timeout)
        except socket.timeout:
            return None, "超时"
        except ConnectionResetError:
            return None, "连接被重置"
        except ssl.SSLCertVerificationError:
            return None, "证书不符(非翻译服务器)"
        except ssl.SSLError:
            return None, "TLS握手失败"
        except OSError:
            return None, "网络不可达/被拒绝"
        except Exception:
            return None, "其他错误"
        if code == 200:
            return ms, "ok"
        if code == 429:
            return ms, "限流429"
        if code:
            last = f"HTTP {code}"
    return None, last


def probe(ip, *a, **k):
    return probe_ex(ip, *a, **k)[0]


def tcp_alive(ip, timeout=3.5):
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        s.close()
        return True
    except Exception:
        return False


def _rand_in(net):
    n = net.num_addresses
    return str(net.network_address + (random.randrange(1, n - 1) if n > 2 else 0))


def gen_candidates(n4, n6, cidrs=None, extra_v4=(), exclude=()):
    """随机候选。指定 cidrs 时只在这些网段内抽样；否则用内置段 + 联网获取的官方段。"""
    nets = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]
    c4 = [n for n in nets if n.version == 4]
    if not c4:
        c4 = [ipaddress.ip_network(r) for r in list(V4_RANGES) + list(extra_v4)]
    c6 = [n for n in nets if n.version == 6]
    v4, v6 = set(), set()
    weights = [n.num_addresses for n in c4]
    for _ in range(n4 * 5):
        if len(v4) >= n4:
            break
        v4.add(_rand_in(random.choices(c4, weights)[0]))
    for _ in range(n6 * 5):
        if len(v6) >= n6:
            break
        if c6:
            v6.add(_rand_in(random.choice(c6)))
        else:  # Google 亚太 IPv6 常见形态 2404:6800:40xx:cxx::xx
            pfx = f"2404:6800:{random.randint(0x4001, 0x4012):x}"
            sub = random.choice([random.randint(0xc00, 0xc3f), random.randint(0x800, 0x83f)])
            suf = random.choice([random.randint(0x5e, 0x9f), 0x2004, 0x200a, 0x2003, 0x200e])
            v6.add(f"{pfx}:{sub:x}::{suf:x}")
    out = [ip for ip in list(v4) + list(v6) if ip not in exclude]
    random.shuffle(out)
    return out


_V6_SUFFIXES = list(range(0x5e, 0xa0)) + list(range(0x2000, 0x2010))


def nat64_addr(prefix, v4):
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(prefix)) | int(ipaddress.IPv4Address(v4))))


def nat64_split(ip):
    """若 ip 属于已知 NAT64 前缀，返回 (前缀, 内嵌的 IPv4)；否则 None。"""
    try:
        x = int(ipaddress.IPv6Address(ip))
    except ValueError:
        return None
    for pfx in NAT64_PREFIXES:
        if (x >> 32) == (int(ipaddress.IPv6Address(pfx)) >> 32):
            return pfx, str(ipaddress.IPv4Address(x & 0xFFFFFFFF))
    return None


def is_nat64(ip):
    return ":" in ip and nat64_split(ip) is not None


def nat64_candidates(deep=False, seeds_only=False, quick=False):
    """NAT64 候选：已知种子 IPv4 × 全部网关前缀，再加 IP 库与 216.239.32.0/19 的抽样。"""
    out = [nat64_addr(p, NAT64_SEED_V4) for p in NAT64_PREFIXES]
    if seeds_only:
        return out
    lib = [i for i in LIB_IPS if ":" not in i]
    random.shuffle(lib)
    if quick:                          # 快速模式：只试少量，避免给志愿者网关增加负担
        return list(dict.fromkeys(out + [nat64_addr(p, v) for v in lib[:6] for p in NAT64_PREFIXES]))
    pool = lib[:20] + [f"216.239.{random.randint(32, 39)}.{random.randint(1, 254)}" for _ in range(40)]
    if deep:
        pool += lib[20:60] + [f"216.239.{random.randint(32, 63)}.{random.randint(1, 254)}" for _ in range(60)]
    out += [nat64_addr(p, v) for v in dict.fromkeys(pool) for p in NAT64_PREFIXES]
    return list(dict.fromkeys(out))


def neighbors(ip):
    """某个可用 IP 的邻居：IPv4 取同 /24；NAT64 取内嵌 IPv4 的同 /24（抽样）；其它 IPv6 取同 /64 常见后缀。"""
    if ":" in ip:
        sp = nat64_split(ip)
        if sp:
            pfx, v4 = sp
            sibs = [str(h) for h in ipaddress.ip_network(v4 + "/24", strict=False).hosts() if str(h) != v4]
            return [nat64_addr(pfx, x) for x in random.sample(sibs, min(60, len(sibs)))]
        base = (int(ipaddress.ip_address(ip)) >> 64) << 64
        return [str(ipaddress.ip_address(base + s)) for s in _V6_SUFFIXES
                if str(ipaddress.ip_address(base + s)) != ip]
    return [str(h) for h in ipaddress.ip_network(ip + "/24", strict=False).hosts() if str(h) != ip]


def learned_candidates(mode, per_net=40):
    """从历史成功过的网段里再抽样（扫描越用越准）。"""
    out = []
    for c in load_nets():
        try:
            net = ipaddress.ip_network(c)
        except ValueError:
            continue
        if (net.version == 4 and mode == "v6") or (net.version == 6 and mode == "v4"):
            continue
        if net.version == 4:
            hosts = [str(h) for h in net.hosts()]
            out += random.sample(hosts, min(per_net, len(hosts)))
        else:
            base = int(net.network_address)
            out += [str(ipaddress.ip_address(base + s))
                    for s in random.sample(_V6_SUFFIXES, min(per_net, len(_V6_SUFFIXES)))]
    return out


# ---- 联网扩展：DoH / 系统 DNS 发现 + Google 官方地址段 -----------------------
DISCOVER_NAMES = [
    "translate.googleapis.com", "www.googleapis.com", "translate.google.com", "www.google.com",
    "clients1.google.com", "www.gstatic.com", "fonts.googleapis.com", "ajax.googleapis.com",
    "storage.googleapis.com", "youtubei.googleapis.com",
]
DOH_SERVERS = [
    "https://dns.alidns.com/resolve", "https://doh.pub/dns-query",
    "https://dns.google/resolve", "https://cloudflare-dns.com/dns-query",
]
OFFICIAL_URL = "https://www.gstatic.com/ipranges/goog.json"


def _http_json(url, timeout=4):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"})
    return json.loads(op.open(req, timeout=timeout).read().decode("utf-8", "ignore"))


def discover_ips(mode="both"):
    """向多个 DoH 服务器和系统 DNS 查询 Google 相关域名，收集 IP（是否可用由探测决定）。"""
    types = ("A",) if mode == "v4" else ("AAAA",) if mode == "v6" else ("A", "AAAA")
    found = set()

    def doh(u):
        try:
            for a in _http_json(u).get("Answer", []):
                if a.get("type") in (1, 28):
                    found.add(str(a.get("data", "")).strip())
        except Exception:
            pass

    def sysdns(n):
        try:
            for info in socket.getaddrinfo(n, 443, proto=socket.IPPROTO_TCP):
                found.add(info[4][0])
        except Exception:
            pass

    jobs = [(doh, f"{s}?name={n}&type={t}") for s in DOH_SERVERS for n in DISCOVER_NAMES for t in types]
    jobs += [(sysdns, n) for n in DISCOVER_NAMES]
    with ThreadPoolExecutor(16) as ex:
        list(ex.map(lambda j: j[0](j[1]), jobs))
    out = []
    for s in found:
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            continue
        if not a.is_global or (mode == "v4" and a.version == 6) or (mode == "v6" and a.version == 4):
            continue
        out.append(str(a))
    return out


def fetch_official_v4():
    try:
        d = _http_json(OFFICIAL_URL, timeout=6)
        return [p["ipv4Prefix"] for p in d.get("prefixes", [])
                if "ipv4Prefix" in p and int(p["ipv4Prefix"].split("/")[1]) <= 24]
    except Exception:
        return []


# ---- 用户自定义范围文件 gtfix_ranges.txt（每行一个 CIDR 或 IP，# 开头为注释）-----
def _app_dir():
    return os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]))


def ranges_path():
    return os.path.join(_app_dir(), "gtfix_ranges.txt")


def load_range_file():
    out = []
    try:
        for line in open(ranges_path(), encoding="utf-8"):
            for tok in line.split("#")[0].replace(",", " ").split():
                if tok.lower().startswith("http"):
                    continue
                try:
                    ipaddress.ip_network(tok, strict=False)
                    out.append(tok)
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def load_sources():
    """范围文件里以 http 开头的行，视为在线 IP 库地址（每行一个，内容为 IP 列表文本）。"""
    out = []
    try:
        for line in open(ranges_path(), encoding="utf-8"):
            for tok in line.split("#")[0].split():
                if tok.lower().startswith("http"):
                    out.append(tok)
    except OSError:
        pass
    return out


def open_range_file():
    p = ranges_path()
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f:
            f.write("# 自定义扫描范围：每行一个 CIDR 或单个 IP，# 开头为注释\n"
                    "# 填写 CIDR 后，规律/随机扫描只在这些范围内进行；单个 IP 会被直接探测\n"
                    "# 以 http 开头的行会被当作在线 IP 库（内容为 IP 列表），例如社区维护的 ips.txt\n"
                    "# 例：\n# 142.250.0.0/16\n# 2404:6800:4008::/48\n")
    if IS_WIN:
        os.startfile(p)
    else:
        subprocess.Popen(["xdg-open" if sys.platform != "darwin" else "open", p])


class _Stopper:
    """把用户的“停止”事件与扫描时间上限合并成一个 is_set() 接口。"""
    def __init__(self, ext=None, seconds=None):
        self.ext, self.timed_out = ext, False
        self.deadline = time.time() + seconds if seconds else None

    def is_set(self):
        if self.ext is not None and self.ext.is_set():
            return True
        if self.deadline is not None and time.time() > self.deadline:
            self.timed_out = True
            return True
        return False


def run_probes(ips, log=print, stop=None, workers=40, enough=None, on_good=None, tcp_workers=150):
    """大批量先做 TCP 443 预筛（高并发），再对连得通的做完整探测（TLS+接口）。"""
    stopped = lambda: stop is not None and stop.is_set()
    total, stats = len(ips), Counter()
    if total > 40:
        alive, done = [], 0
        ex = ThreadPoolExecutor(tcp_workers)
        futs = {ex.submit(tcp_alive, ip): ip for ip in ips}
        try:
            for f in as_completed(futs):
                if stopped():
                    log("已达时间上限，结束本批。" if getattr(stop, "timed_out", False) else "已停止。")
                    return []
                done += 1
                if f.result():
                    alive.append(futs[f])
                if done % 500 == 0:
                    log(f"  …TCP 预筛 {done}/{total}，443 端口可连通 {len(alive)}")
        finally:
            for f in futs:
                f.cancel()
            ex.shutdown(wait=False)
        stats["TCP 443 不通"] = total - len(alive)
        _alive = set(alive)
        for _ip in alive:
            SCAN_ALIVE["v6" if ":" in _ip else "v4"] += 1
        for _ip in ips:
            if _ip not in _alive:
                SCAN_STATS[("v6" if ":" in _ip else "v4", "TCP 443 不通")] += 1
        log(f"  TCP 预筛完成：{len(alive)}/{total} 个可连通")
        ips = alive
    good, done, n = [], 0, len(ips)
    ex = ThreadPoolExecutor(workers)
    futs = {ex.submit(probe_ex, ip): ip for ip in ips}
    try:
        for f in as_completed(futs):
            if stopped():
                log("已达时间上限，结束本批。" if getattr(stop, "timed_out", False) else "已停止。")
                break
            done += 1
            ms, why = f.result()
            ip = futs[f]
            if ms is not None:
                good.append((ip, ms))
                log(f"  ✔ {ip}  {min(ms, 9999):.0f} ms" + ("" if why == "ok" else f"  ({why})"))
                if on_good:
                    on_good(ip, ms)
                if enough and enough(good):
                    break
            else:
                stats[why] += 1
                SCAN_STATS[("v6" if ":" in ip else "v4", why)] += 1
            if n > 60 and done % 100 == 0:
                log(f"  …完整探测 {done}/{n}，可用 {len(good)}")
    finally:
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False)
    if not good and stats:
        log("  失败原因统计：" + "、".join(f"{k} {v}" for k, v in stats.most_common()))
    good.sort(key=lambda x: x[1])
    return good


def stable_filter(good, tries=3, per_family=8, log=print, stop=None):
    """稳定性复测：每个候选再测 tries-1 次，全部成功才算稳定（参考 GoogleTranslate_IPFinder 的做法）。"""
    ordered = sorted(good, key=lambda x: x[1])
    cand = [x for x in ordered if ":" not in x[0]][:per_family] + [x for x in ordered if ":" in x[0]][:per_family]
    if not cand or (stop is not None and stop.is_set()):
        return cand
    res = {ip: [ms] for ip, ms in cand}
    jobs = [ip for ip in res for _ in range(tries - 1)]
    with ThreadPoolExecutor(16) as ex:
        for ip, (ms, _) in zip(jobs, ex.map(probe_ex, jobs)):
            res[ip].append(ms)
    full, part = [], []
    for ip, l in res.items():
        ok = [x for x in l if x is not None]
        if len(ok) == tries:
            full.append((ip, sum(ok) / len(ok)))
        elif len(ok) >= 2:
            part.append((ip, sum(ok) / len(ok)))
    out = full or part
    log(f"  稳定性复测：{len(full)} 个全部通过，{len(part)} 个部分通过")
    return sorted(out, key=lambda x: x[1])


def detect_env(log=print):
    """检测代理 / TUN / fake-ip：它们会让探测结果失真（全部超时，或全部'假成功'）。"""
    notes = []
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        if os.environ.get(k):
            notes.append(f"环境变量 {k}={os.environ[k]}")
            break
    if IS_WIN:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
                if winreg.QueryValueEx(k, "ProxyEnable")[0]:
                    try:
                        notes.append("系统代理已开启：" + str(winreg.QueryValueEx(k, "ProxyServer")[0]))
                    except OSError:
                        notes.append("系统代理已开启")
        except Exception:
            pass
    try:
        for info in socket.getaddrinfo("www.google.com", 443, proto=socket.IPPROTO_TCP):
            if info[4][0].startswith(("198.18.", "198.19.")):
                notes.append("检测到 fake-ip 解析（Clash/Mihomo 等 TUN 模式）")
                break
    except Exception:
        pass
    if notes:
        log("⚠ 检测到代理/虚拟网卡迹象：" + "；".join(notes))
        log("  这会让探测失真：要么全部超时，要么全部“假成功”（流量其实走了代理）。"
            "请先完全关闭代理 / TUN 再扫描。")
    return notes


def _parse_ips(text):
    out = []
    for tok in re.split(r"[\s,;]+", text):
        try:
            a = ipaddress.ip_address(tok.strip())
        except ValueError:
            continue
        if a.is_global:
            out.append(str(a))
    return list(dict.fromkeys(out))[:20000]


def fetch_library(extra=(), log=print):
    """导入在线 IP 库：自定义 URL 全部读取；内置镜像并行请求，任一成功即可。"""
    def get(u):
        req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
        return _parse_ips(urllib.request.urlopen(req, timeout=6).read().decode("utf-8", "ignore"))
    got = []
    for u in extra:
        try:
            ips = get(u)
            got += ips
            log(f"已导入自定义 IP 库：{len(ips)} 个（{u}）")
        except Exception:
            log(f"自定义 IP 库读取失败：{u}")
    ex = ThreadPoolExecutor(len(LIB_URLS))
    futs = {ex.submit(get, u): u for u in LIB_URLS}
    found = False
    try:
        for f in as_completed(futs, timeout=10):
            try:
                ips = f.result()
            except Exception:
                continue
            if ips:
                got += ips
                log(f"已导入在线 IP 库：{len(ips)} 个（{futs[f]}）")
                found = True
                break
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    if not found:
        log("在线 IP 库镜像均不可达，使用内置库。")
    return list(dict.fromkeys(got))


def pattern_candidates(deep=False):
    """
    规律扫描：已知可用 IP 绝大多数形如 a.b.c.90（googleapis 前端）。
    对每个已知 /16（a.b）枚举全部第三段 c，固定末段 .90，命中率远高于全段盲抽。
    深度模式额外抽样其它常见末段。
    """
    known = [i for i in LIB_IPS + load_cache() if ":" not in i]
    prefixes = {".".join(i.split(".")[:2]) for i in known}
    prefixes |= {"142.250", "142.251", "172.217", "172.253", "108.177", "216.58", "74.125", "64.233",
                 "209.85", "173.194", "192.178", "192.179"}
    base = [f"{p}.{c}.90" for p in sorted(prefixes) for c in range(256)]
    random.shuffle(base)
    if deep:
        sufs = [14, 142, 174, 46, 238, 100, 101, 138, 186, 206, 65, 66, 67]
        extra = [f"{p}.{random.randrange(256)}.{random.choice(sufs)}" for p in sorted(prefixes) for _ in range(250)]
        base += list(dict.fromkeys(extra))
    return base


def do_scan(mode="both", n4=600, n6=300, cidrs=None, per_family=4, deep=False, online=True,
            sources=None, log=print, stop=None, on_good=None, diag=True, pre_tried=None, use_shared=False,
            quick=False, budget=None):
    """
    分阶段扫描（参考 hcfyapp / Ponderfly / GoodCoder666 等项目的做法）：
      0 自定义 IP   1 历史+内置 IP 库   2 联网：在线 IP 库 / DoH 发现 / 官方地址段
      3 .90 规律扫描（3b NAT64 网关）   4 随机抽样（深度多轮）   5 邻近扩展（命中 IP 的整个 /24 或 /64）
    quick=True 为快速扫描：只抽样 .90 规律候选、少量 NAT64、不做随机抽样，IPv4 / IPv6 各收集少量可用 IP 即结束，
    并受 budget（秒）限制，用于首次使用时快速建立本地库。
    自定义范围（--cidr / 界面输入框 / gtfix_ranges.txt）存在时，规律与随机扫描只在其内进行。
    """
    v6_local = has_ipv6()
    want4 = mode != "v6"
    want6 = mode != "v4" and v6_local
    if mode != "v4":
        ipv6_report(log)
    if mode != "v4" and not v6_local:
        log("提示：本机没有可用的 IPv6 外网连接，跳过 IPv6 扫描。")
    if not want4 and not want6:
        return []
    if diag:
        detect_env(log)
    if deep:
        n4, n6, per_family = n4 * 2, n6 * 2, max(per_family, 8)
    if quick:
        per_family = max(per_family, 6)
    if budget:
        stop = _Stopper(stop, budget)
    cidrs = list(cidrs or []) + load_range_file()
    sources = list(sources or []) + load_sources()
    if cidrs:
        log(f"使用自定义范围：{len(cidrs)} 条")
    global SCAN_DEAD4
    SCAN_STATS.clear()
    SCAN_ALIVE.clear()
    SCAN_DEAD4 = False
    dead4, dead6 = [False], [False]
    tried, good = set(pre_tried or ()), []
    stopped = lambda: stop is not None and stop.is_set()
    famok = lambda ip: ((":" in ip and want6 and not dead6[0])
                        or (":" not in ip and want4 and not dead4[0]))

    def check_dead():
        global SCAN_DEAD4
        n404 = SCAN_STATS[("v4", "HTTP 404")]
        other = sum(v for (f, k), v in SCAN_STATS.items()
                    if f == "v4" and k not in ("HTTP 404", "TCP 443 不通"))
        if (not dead4[0] and n404 >= 60 and n404 >= 9 * other
                and not any(":" not in ip for ip, _ in good)):
            dead4[0] = SCAN_DEAD4 = True
            log("判定：能连通的节点几乎全部返回 HTTP 404（连到的是不提供翻译接口的节点），"
                "继续扫 IPv4 意义不大，停止 IPv4 扫描。")

    def check_dead6():
        if (want6 and not dead6[0] and SCAN_ALIVE["v6"] == 0
                and SCAN_STATS[("v6", "TCP 443 不通")] >= 150 and not any(":" in ip for ip, _ in good)):
            dead6[0] = True
            log(f"判定：已测 {SCAN_STATS[('v6', 'TCP 443 不通')]} 个 IPv6 候选，TCP 443 全部不通 —— "
                "本机 IPv6 到不了 Google，也到不了 NAT64 网关，停止 IPv6 扫描（IPv4 可用时不影响使用）。")

    pf4, pf6 = per_family, (max(2, per_family // 2) if quick else per_family)

    def counts(g):
        return (sum(1 for ip, _ in g if ":" not in ip), sum(1 for ip, _ in g if ":" in ip))

    def enough(g):
        a, b = counts(g)
        if quick:       # 快速扫描：IPv4 / IPv6 都要凑够（不通的一方不计）
            return (not want4 or dead4[0] or a >= pf4) and (not want6 or dead6[0] or b >= pf6)
        return (want4 and a >= pf4) or (want6 and b >= pf6)

    def batch(ips, title, slow=False):
        ips = [i for i in dict.fromkeys(ips) if i not in tried and famok(i)]
        if quick:       # 已凑够的一方不再继续扫
            a0, b0 = counts(good)
            ips = [i for i in ips if (b0 < pf6 if ":" in i else a0 < pf4)]
        if not ips or stopped() or enough(good):
            return
        tried.update(ips)
        fams = {"v6" if ":" in i else "v4" for i in ips}

        def batch_enough(g):
            if not quick:
                return enough(good + g)
            a, b = counts(good + g)
            return all((a >= pf4) if f == "v4" else (b >= pf6) for f in fams)

        log(f"{title}：{len(ips)} 个候选 …")
        good.extend(run_probes(ips, log, stop, workers=20 if slow else 40, tcp_workers=40 if slow else 150,
                               enough=batch_enough, on_good=on_good))
        check_dead()
        check_dead6()

    exact = [c.split("/")[0] for c in cidrs if c.endswith(("/32", "/128")) or "/" not in c]
    cidrs = [c for c in cidrs if c not in exact and not c.endswith(("/32", "/128"))]
    batch(exact, "阶段0·自定义 IP")
    if use_shared and online and _shared_repo() and not stopped():
        batch(fetch_shared(log), "阶段0b·共享库")
    batch(load_cache() + PRESET_V4 + learned_candidates(mode), "阶段1·历史 / 内置 IP 库")
    extra_v4 = []
    if online and not stopped() and not enough(good):
        log("阶段2·联网扩展 …")
        batch(fetch_library(sources, log), "阶段2a·在线 IP 库")
        batch(discover_ips(mode), "阶段2b·DNS 发现")
        if not quick and not cidrs and want4 and not stopped() and not enough(good):
            extra_v4 = fetch_official_v4()
            log(f"获取到官方 IPv4 地址段 {len(extra_v4)} 个" if extra_v4 else "官方地址段不可获取，跳过。")
    if want4 and not cidrs:
        pc = pattern_candidates(deep)
        batch(pc[:1500] if quick else pc, "阶段3·.90 规律扫描" + ("（抽样）" if quick else ""))
    if want6 and not cidrs:
        batch(nat64_candidates(deep, quick=quick), "阶段3b·NAT64 网关（IPv6 → Google IPv4）", slow=True)
    for r in range(0 if quick else (3 if deep else 1)):
        if stopped() or enough(good):
            break
        cands = gen_candidates(n4 if want4 else 0, n6 if want6 else 0, cidrs, extra_v4, tried)
        batch(cands, f"阶段4·随机抽样 第{r + 1}轮")
    seen = set()
    for ip, _ in sorted(good, key=lambda x: x[1]):
        if quick and enough(good):          # 快速扫描：已够用就不再做邻近扩展
            break
        key = ip.rsplit(".", 1)[0] if ":" not in ip else ip.rsplit(":", 1)[0]
        if key in seen or len(seen) >= (2 if quick else 3) or stopped():
            continue
        seen.add(key)
        ips = [i for i in neighbors(ip) if i not in tried]
        if ips:
            tried.update(ips)
            log(f"阶段5·邻近扩展 {ip}：{len(ips)} 个候选 …")
            good.extend(run_probes(ips, log, stop, on_good=on_good))
    uniq = {}
    for ip, ms in good:
        uniq[ip] = min(ms, uniq.get(ip, ms))
    good = sorted(uniq.items(), key=lambda x: x[1])
    if good:
        save_cache([ip for ip, _ in good])
    if want6 and (quick or deep) and not stopped():
        mark_v6(any(":" in ip for ip, _ in good))
    n4_, n6_ = counts(good)
    log(f"扫描结束，找到 {len(good)} 个可用 IP（IPv4 {n4_} 个 / IPv6 {n6_} 个）。")
    return good



# =============================================================================
# 三、缓存 / 验证 / 一键修复
# =============================================================================
def _cache_path():
    return os.path.join(_app_dir(), "gtfix_ips.json")


def _load_cache_raw():
    try:
        d = json.load(open(_cache_path(), encoding="utf-8"))
        return d if d.get("ver") == 2 else {}      # 旧版缓存里混有 404 节点，直接丢弃
    except Exception:
        return {}


def load_cache():
    return _load_cache_raw().get("ips", [])


def load_nets():
    return _load_cache_raw().get("nets", [])


def _write_cache(d):
    try:
        d["ver"] = 2
        json.dump(d, open(_cache_path(), "w", encoding="utf-8"))
    except Exception:
        pass


def save_cache(ips):
    """记住可用 IP，并记住它们所在网段（IPv4 /24、IPv6 /64），供下次扫描优先抽样。"""
    d = dict(_load_cache_raw())
    nets = []
    for ip in ips:
        if is_nat64(ip):
            continue
        try:
            nets.append(str(ipaddress.ip_network(ip + ("/64" if ":" in ip else "/24"), strict=False)))
        except ValueError:
            pass
    d["ips"] = list(dict.fromkeys(list(ips) + d.get("ips", [])))[:60]
    d["nets"] = list(dict.fromkeys(nets + d.get("nets", [])))[:60]
    _write_cache(d)


def mark_v6(found):
    """记录 IPv6 扫描结果：近期扫不到就先记下来，24 小时内一键修复不再白等 IPv6。"""
    d = dict(_load_cache_raw())
    if found:
        d.pop("v6_dead_ts", None)
    else:
        d["v6_dead_ts"] = time.time()
    _write_cache(d)


def v6_recently_dead(hours=24):
    return time.time() - _load_cache_raw().get("v6_dead_ts", 0) < hours * 3600


def prune_cache(alive):
    """从本地库移除已失效的 IP（仅在至少有一个可用时调用，避免网络抖动时清空整个库）。"""
    d = dict(_load_cache_raw())
    if not d:
        return
    alive = set(alive)
    d["ips"] = [i for i in d.get("ips", []) if i in alive]
    _write_cache(d)


def verify(log=print):
    """走系统解析（即 hosts）真实请求翻译接口。刻意绕过系统代理。任一路径返回 200 即通过。"""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    errs = []
    for path in PROBE_PATHS:
        try:
            r = op.open(f"https://{HOST}{path}", timeout=10)
            r.read(2048)
            if r.status == 200:
                log("✅ 验证通过：翻译接口可正常访问。")
                return True
            errs.append(f"{path} → HTTP {r.status}")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                log("✅ 线路已通（接口对验证请求限流 429，属正常；Chrome 翻译请求量小，一般不受影响）。")
                return True
            errs.append(f"{path} → HTTP {e.code}")
        except Exception as e:
            errs.append(f"{path} → {e}")
    log("⚠ 验证失败：" + "；".join(errs))
    return False


def pick(good, mode, keep):
    v4 = [ip for ip, _ in good if ":" not in ip][:keep]
    v6 = [ip for ip, _ in good if ":" in ip][:keep]
    return v4 if mode == "v4" else v6 if mode == "v6" else v4 + v6


def do_apply(ips, log=print, path=None, verify_after=True):
    apply_ips(ips, path)
    save_cache(ips)
    log("已写入 hosts：" + ", ".join(ips))
    if path in (None, HOSTS):
        flush_dns()
        log("已刷新 DNS 缓存。请完全退出并重启 Chrome 后再试翻译。")
        if verify_after:
            return verify(log)
    return True


def do_fix(mode="both", auto_scan=True, keep=2, cidrs=None, log=print, stop=None,
           on_good=None, path=None, verify_after=True, online=True, deep=False, sources=None,
           use_shared=True):
    """
    一键修复（默认 IPv4 + IPv6 都修复）：
      1 本地库：先测试上次建好的本地库，有稳定可用的就直接应用
      2 快速扫描（约 1 分钟）：首次使用（本地库为空）或本地库已失效时，IPv4 / IPv6 一起扫，
        结果存入本地库 → 对这些 IP 复测延迟 → 挑最快最稳的写入 hosts
      3 深度扫描：快速扫描没找到可用 IP 时才启动，耗时更长
      4 补齐：已应用但缺 IPv4 或 IPv6 其中一族时，只针对缺的那一族再做一次快速扫描
    """
    stopped = lambda: stop is not None and stop.is_set()
    detect_env(log)
    v6_ok = has_ipv6() if mode != "v4" else False
    v6_skip = mode == "both" and v6_ok and v6_recently_dead()
    v6_local = v6_ok and not v6_skip
    if v6_skip:
        log("ℹ 近期 IPv6 扫描没有结果，本次先跳过 IPv6（选择「仅 IPv6」可强制重试）。")
    scan_mode = "v4" if (mode == "both" and not v6_local) else mode
    famok = lambda ip: (":" in ip and mode != "v4" and v6_local) or (":" not in ip and mode != "v6")
    last = [[]]          # 最近一次成功应用的稳定 IP 列表

    def try_apply(st):
        first = pick(st, mode, keep)
        if not first:
            return False
        ok = do_apply(first, log, path, verify_after)
        if ok:
            last[0] = [(i, m) for i, m in st if i in first]
            hint_share(log, path)
        if ok or path not in (None, HOSTS) or not verify_after:
            return ok
        for ip in [i for i, _ in st if i not in first][:4]:
            if stopped():
                break
            log(f"端到端验证未通过，改试 {ip} …")
            if do_apply([ip], log, path, verify_after):
                last[0] = [(i, m) for i, m in st if i == ip]
                hint_share(log, path)
                return True
        log("候选 IP 均未通过端到端验证。")
        return False

    def finalize(good):
        if not good:
            return False
        log("复测延迟与稳定性（每个 IP 共 3 次）…")
        st = stable_filter(good, log=log, stop=stop)
        if not st:
            log("复测均未通过，这些 IP 不稳定。")
            return False
        return try_apply(st)

    kw = dict(cidrs=cidrs, log=log, stop=stop, on_good=on_good, online=online, sources=sources,
              diag=False, use_shared=use_shared)

    def complete():
        """已成功应用：默认 IPv4+IPv6 都修复，缺哪一族就只针对它补做一次快速扫描。"""
        if mode != "both":
            return True
        for fam, name in (("v4", "IPv4"), ("v6", "IPv6")):
            if stopped() or (fam == "v6" and (not v6_local or v6_recently_dead())):
                continue
            have = any((":" in i) == (fam == "v6") for i, _ in last[0])
            if have:
                continue
            log(f"{name} 还没有可用地址，针对它补做快速扫描 …")
            g = do_scan(fam, quick=True, budget=60, pre_tried=lib, **kw)
            if g:
                finalize(g + last[0])        # 合并后重新复测并应用
        if mode == "both" and v6_local and not any(":" in i for i, _ in last[0]):
            log("ℹ 暂未找到可用的 IPv6 地址，目前只修复了 IPv4（Chrome 会正常使用 IPv4）。")
        return True

    lib = [i for i in load_cache() if famok(i)]
    if lib and not deep:
        log(f"第 1 步：测试本地库 {len(lib)} 个 IP …")
        good = run_probes(lib, log, stop, on_good=on_good)
        if good and not stopped():
            prune_cache([ip for ip, _ in good])        # 清理失效 IP，保持本地库健康
        if finalize(good):
            return complete()
        if stopped():
            return False
        log("本地库已失效，进入快速扫描 …")
    elif not deep:
        log("首次使用（本地库为空）：先做快速扫描，建立本地库 …")

    if not deep:
        log("第 2 步：快速扫描（约 1 分钟" + ("，IPv4 与 IPv6 一起扫" if scan_mode == "both" else "") + "）…")
        if finalize(do_scan(scan_mode, quick=True, budget=90, pre_tried=lib, **kw)):
            return complete()
    if (auto_scan or deep) and not stopped():
        log("快速扫描未找到可用 IP，启动深度扫描（耗时较长，可随时点「停止」）…" if not deep
            else "启动深度扫描（耗时较长，可随时点「停止」）…")
        if finalize(do_scan(scan_mode, deep=True, pre_tried=lib, **kw)):
            return complete()
    log("❌ 没有找到可用的 IP。")
    log("  · 若失败原因大多是 HTTP 404：连到的是不提供翻译接口的节点（例如境内的 Google 节点），"
        "可尝试 IPv6 / NAT64 通道。"
        + ("本机 IPv6：可用，已尝试 NAT64。" if v6_local else "本机 IPv6：不可用（开启后才能用 NAT64）。"))
    log("  · 若大多是超时 / TCP 不通：请先完全关闭代理与 TUN，或换网络（如手机热点）再试。")
    log("  · 可点「诊断」按钮（或 --diagnose）把输出发给开发者分析。")
    return False


def _shared_repo():
    r = (os.environ.get("GTFIX_SHARED_REPO") or SHARED_REPO or "").strip().strip("/")
    return r if re.fullmatch(r"[\w.-]+/[\w.-]+", r) else ""


def shared_urls():
    r = _shared_repo()
    if not r:
        return []
    return [f"https://cdn.jsdelivr.net/gh/{r}@{SHARED_BRANCH}/{SHARED_FILE}",
            f"https://fastly.jsdelivr.net/gh/{r}@{SHARED_BRANCH}/{SHARED_FILE}",
            f"https://raw.githubusercontent.com/{r}/{SHARED_BRANCH}/{SHARED_FILE}"]


def _fetch_ips(u, timeout=8):
    req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
    return _parse_ips(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore"))


def fetch_shared(log=print, limit=300):
    """读取共享可用 IP 库（jsDelivr 优先，GitHub raw 兜底；并行请求，任一成功即可）。文件越靠前越新。"""
    urls = shared_urls()
    if not urls:
        return []
    ex = ThreadPoolExecutor(len(urls))
    futs = {ex.submit(_fetch_ips, u, 6): u for u in urls}
    try:
        for f in as_completed(futs, timeout=10):
            try:
                ips = f.result()[:limit]
            except Exception:
                continue
            if ips:
                log(f"已获取共享可用 IP：{len(ips)} 个")
                return ips
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    log("共享 IP 库不可达或为空，跳过。")
    return []


def _shareable(limit=30):
    ips = []
    try:
        ips += block_ips()          # 当前写入 hosts 并通过验证的
    except Exception:
        pass
    ips += load_cache()             # 本机扫描验证过的
    return list(dict.fromkeys(ips))[:limit]


def share_ips(ips=None, log=print, open_browser=True):
    """
    分享可用 IP：在浏览器打开 GitHub 预填好的 Issue，只包含 IP 列表；你确认并点 Submit 后才会提交。
    不在程序里保存任何 GitHub 令牌，也不会后台上传任何数据。
    """
    repo = _shared_repo()
    if not repo:
        log("未配置共享库：请在 gtfix.py 顶部设置 SHARED_REPO（或使用 --shared-repo 用户名/仓库名）。")
        return False
    ips = ips or _shareable()
    if not ips:
        log("没有可分享的 IP：请先成功运行一次「一键修复」或「扫描」。")
        return False
    body = ("由 ChromeTranslateFix 生成。以下 IP 已在提交者的网络里通过 TLS 证书校验与接口探测。\n\n"
            "```\n" + "\n".join(ips) + "\n```\n")
    url = f"https://github.com/{repo}/issues/new?title={quote('[IP] 共享可用 IP')}&body={quote(body)}"
    log("将在浏览器打开 GitHub 预填的 Issue，内容仅为下面的 IP 列表；你检查后点 Submit 才会提交（需登录 GitHub，提交会公开显示你的账号）：")
    log("\n".join("  " + i for i in ips))
    log("如果浏览器没有自动打开，请复制此链接：\n" + url)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    return True


def export_ips(path="-", log=print):
    """把本机验证过的 IP 导出成 ips.txt 格式（仓库维护者可直接粘贴进仓库）。"""
    lines = [f"{ip}  # {time.strftime('%Y-%m-%d')}" for ip in _shareable(50)]
    if path in ("-", ""):
        print("\n".join(lines))
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log(f"已导出 {len(lines)} 个 IP 到 {path}")


def hint_share(log, path=None):
    if _shared_repo() and path in (None, HOSTS):
        log("💡 这些 IP 对你有效。点「分享可用 IP」（命令行 --share）可帮助其他用户，提交前你可以先查看内容。")


def do_test(log=print):
    ips = block_ips()
    if not ips:
        log("hosts 中还没有本工具写入的记录。")
    for ip in ips:
        ms = probe(ip)
        log(f"  {'✔' if ms else '✘'} {ip}  {'%.0f ms' % ms if ms else '不可用'}")
    return verify(log)


def diagnose(log=print):
    """输出一份诊断报告：各候选 IP 对各接口路径的 HTTP 状态、Server 头、正文片段。"""
    detect_env(log)
    log(f"本机 IPv6：{'可用' if has_ipv6() else '不可用'}")
    ips = []
    try:
        ips += block_ips()
    except Exception:
        pass
    ips += [i for i in LIB_IPS if ":" not in i][:3] + ["183.56.143.147"]
    if has_ipv6():
        ips += nat64_candidates(seeds_only=True)[:3]
    for ip in dict.fromkeys(ips):
        for path in PROBE_PATHS + ["/translate_static/js/element/main.js"]:
            try:
                code, h, body, ms = _http_get(ip, path, want_body=True)
                snippet = body[:90].decode("utf-8", "ignore").replace("\r", " ").replace("\n", " ")
                log(f"{ip}  {path[:32]}\n    → HTTP {code}  {ms:.0f}ms  Server={h.get('server', '?')}  {snippet!r}")
            except Exception as e:
                log(f"{ip}  {path[:32]}\n    → 失败：{type(e).__name__} {e}")
    log("诊断结束。请把以上输出完整发给开发者。")


def status_text():
    try:
        ips = block_ips()
    except Exception as e:
        return f"无法读取 hosts：{e}"
    return ("已修复：" + "  ".join(ips)) if ips else "未修复（hosts 中没有本工具的记录）"


# =============================================================================
# 四、提权
# =============================================================================
def relaunch_admin(gui=False, extra=()):
    exe = sys.executable
    frozen = getattr(sys, "frozen", False)
    args = sys.argv[1:] if frozen else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    if gui and not frozen and exe.lower().endswith("python.exe"):
        w = exe[:-10] + "pythonw.exe"
        if os.path.exists(w):
            exe = w
    params = " ".join('"%s"' % a for a in list(args) + list(extra))
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32


# =============================================================================
# 五、图形界面
# =============================================================================
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title("Chrome 翻译一键修复工具")
    root.geometry("760x600")
    q = queue.Queue()
    stop = threading.Event()
    busy = [False]
    log = lambda m: q.put(("log", m))
    on_good = lambda ip, ms: q.put(("row", ip, ms))

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    status = tk.StringVar(value=status_text())
    ttk.Label(top, textvariable=status, foreground="#1a5fb4").pack(anchor="w")

    opt = ttk.Frame(root, padding=(8, 0))
    opt.pack(fill="x")
    mode = tk.StringVar(value="both")
    for text, val in (("IPv4 + IPv6", "both"), ("仅 IPv4", "v4"), ("仅 IPv6", "v6")):
        ttk.Radiobutton(opt, text=text, value=val, variable=mode).pack(side="left", padx=4)
    auto = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt, text="快速扫描无结果时自动深度扫描", variable=auto).pack(side="left", padx=12)
    allh = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt, text="映射全部 4 个域名", variable=allh).pack(side="left", padx=4)
    opt2 = ttk.Frame(root, padding=(8, 2))
    opt2.pack(fill="x")
    deep = tk.BooleanVar(value=False)
    online = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt2, text="深度扫描（更多轮次）", variable=deep).pack(side="left", padx=4)
    ttk.Checkbutton(opt2, text="联网扩展（DoH 发现 / 官方地址段）", variable=online).pack(side="left", padx=4)
    ttk.Label(opt2, text="自定义范围:").pack(side="left", padx=(12, 2))
    cidr_var = tk.StringVar()
    ttk.Entry(opt2, textvariable=cidr_var, width=28).pack(side="left")
    ttk.Button(opt2, text="范围文件", width=8, command=lambda: open_range_file()).pack(side="left", padx=4)

    def get_cidrs():
        toks = cidr_var.get().replace(",", " ").replace(";", " ").split()
        ok = []
        for t in toks:
            try:
                ipaddress.ip_network(t, strict=False)
                ok.append(t)
            except ValueError:
                pass
        return ok

    bar = ttk.Frame(root, padding=8)
    bar.pack(fill="x")
    btns = []

    def mk(text, cmd, big=False):
        b = ttk.Button(bar, text=text, command=cmd, width=14 if big else 10)
        b.pack(side="left", padx=3)
        btns.append(b)
        return b

    cols = ("ip", "fam", "ms")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=8, selectmode="extended")
    for c, t, w in (("ip", "IP 地址", 380), ("fam", "协议", 80), ("ms", "延迟(ms)", 100)):
        tree.heading(c, text=t)
        tree.column(c, width=w, anchor="w")
    tree.pack(fill="x", padx=8)

    txt = tk.Text(root, height=14, state="disabled", wrap="word")
    txt.pack(fill="both", expand=True, padx=8, pady=8)

    def append(m):
        txt.configure(state="normal")
        txt.insert("end", m + "\n")
        txt.see("end")
        txt.configure(state="disabled")

    def set_busy(v):
        busy[0] = v
        for b in btns:
            b.configure(state="disabled" if v else "normal")

    def resort():
        items = sorted(tree.get_children(), key=lambda i: float(tree.set(i, "ms")))
        for idx, i in enumerate(items):
            tree.move(i, "", idx)

    def poll():
        try:
            while True:
                m = q.get_nowait()
                if m[0] == "log":
                    append(m[1])
                elif m[0] == "row":
                    if not any(tree.set(i, "ip") == m[1] for i in tree.get_children()):
                        tree.insert("", "end", values=(m[1], "IPv6" if ":" in m[1] else "IPv4", f"{m[2]:.0f}"))
                elif m[0] == "done":
                    set_busy(False)
                    resort()
                    status.set(status_text())
        except queue.Empty:
            pass
        root.after(100, poll)

    def start(task):
        if busy[0]:
            return
        stop.clear()
        set_hosts_mode(allh.get())
        set_busy(True)

        def w():
            try:
                task()
            except PermissionError:
                log("❌ 没有写入 hosts 的权限：请以管理员身份运行（杀毒软件也可能拦截，请放行）。")
            except Exception as e:
                log(f"❌ 出错：{e}")
            finally:
                q.put(("done",))

        threading.Thread(target=w, daemon=True).start()

    def clear_rows():
        tree.delete(*tree.get_children())

    def on_fix():
        clear_rows()
        start(lambda: do_fix(mode.get(), auto.get(), cidrs=get_cidrs(), log=log, stop=stop,
                             on_good=on_good, online=online.get(), deep=deep.get()))

    def on_scan():
        clear_rows()
        start(lambda: do_scan(mode.get(), cidrs=get_cidrs(), deep=deep.get(), online=online.get(),
                              log=log, stop=stop, on_good=on_good))

    def on_apply():
        ips = [tree.set(i, "ip") for i in tree.selection()]
        if not ips:
            messagebox.showinfo("提示", "请先在列表中选择要写入的 IP（可多选）。")
            return
        start(lambda: do_apply(ips, log))

    def on_restore():
        if messagebox.askyesno("确认", "移除本工具写入的 hosts 记录并还原？"):
            def t():
                restore_hosts()
                flush_dns()
                log("已还原 hosts。")
            start(t)

    mk("一键修复", on_fix, True)
    mk("扫描 IP", on_scan)
    mk("应用选中", on_apply)
    mk("测试当前", lambda: start(lambda: do_test(log)))
    mk("诊断", lambda: start(lambda: diagnose(log)))
    mk("还原", on_restore)
    ttk.Button(bar, text="停止", command=stop.set, width=6).pack(side="left", padx=3)

    append("提示：点「一键修复」即可（默认 IPv4 + IPv6 都修复）。首次使用会先快速扫描（约 1 分钟）建立本地库，之后优先使用本地库；"
           "找不到可用 IP 时会自动深度扫描。也可手动「扫描 IP」后挑选并「应用选中」。")
    append("修复完成后请完全退出并重启 Chrome。")
    poll()
    root.mainloop()


# =============================================================================
# 六、命令行入口
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="Chrome 翻译一键修复工具（hosts + IP 扫描，支持 IPv6）")
    ap.add_argument("--fix", action="store_true", help="一键修复")
    ap.add_argument("--scan", action="store_true", help="仅扫描并列出可用 IP")
    ap.add_argument("--test", action="store_true", help="测试 hosts 中当前的 IP")
    ap.add_argument("--status", action="store_true", help="查看当前状态")
    ap.add_argument("--diagnose", action="store_true", help="输出诊断报告（各 IP/接口的 HTTP 状态等）")
    ap.add_argument("--shared-repo", metavar="用户名/仓库名", help="共享可用 IP 库所在的 GitHub 仓库")
    ap.add_argument("--no-shared", action="store_true", help="不使用共享 IP 库")
    ap.add_argument("--share", action="store_true", help="把本机验证过的可用 IP 分享到共享库（打开预填的 GitHub Issue）")
    ap.add_argument("--export", nargs="?", const="-", metavar="文件", help="导出本机验证过的 IP（ips.txt 格式）")
    ap.add_argument("--main-host-only", action="store_true", help="只映射 translate.googleapis.com 一个域名")
    ap.add_argument("--restore", action="store_true", help="还原 hosts")
    ap.add_argument("--set", nargs="+", metavar="IP", help="手动写入指定 IP（IPv4/IPv6 均可）")
    ap.add_argument("--ipv4", action="store_true", help="只用 IPv4")
    ap.add_argument("--ipv6", action="store_true", help="只用 IPv6")
    ap.add_argument("--no-scan", action="store_true", help="预制 IP 不可用时不自动扫描")
    ap.add_argument("--source", action="append", help="额外的在线 IP 库地址（内容为 IP 列表），可多次指定")
    ap.add_argument("--quick", action="store_true", help="快速扫描（约 1 分钟，用于建立本地库）")
    ap.add_argument("--deep", action="store_true", help="深度扫描（多轮、候选量更大）")
    ap.add_argument("--offline", action="store_true", help="不联网扩展（跳过 DoH 发现与官方地址段）")
    ap.add_argument("--cidr", action="append", help="自定义扫描网段，可多次指定")
    ap.add_argument("--hosts-file", help=argparse.SUPPRESS)  # 测试用
    ap.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    mode = "v4" if a.ipv4 and not a.ipv6 else "v6" if a.ipv6 and not a.ipv4 else "both"
    set_hosts_mode(not a.main_host_only)
    if a.shared_repo:
        os.environ["GTFIX_SHARED_REPO"] = a.shared_repo
    cli = any([a.fix, a.scan, a.test, a.status, a.restore, a.set, a.diagnose, a.share, a.export is not None])
    needs_admin = (a.fix or a.restore or a.set or not cli) and not a.hosts_file

    if needs_admin and not is_admin():
        if IS_WIN:
            if relaunch_admin(gui=not cli, extra=() if not cli else ("--elevated",)):
                return
            print("需要管理员权限，但提权被取消。")
            return
        print("需要 root 权限，请使用：sudo python3 gtfix.py ...")
        return

    path = a.hosts_file
    try:
        if not cli:
            try:
                run_gui()
            except ImportError:
                ap.print_help()
            return
        if a.status:
            print(status_text() if not path else "已写入：" + ", ".join(block_ips(path)))
        if a.restore:
            restore_hosts(path)
            if not path:
                flush_dns()
            print("已还原 hosts。")
        if a.set:
            do_apply(a.set, print, path)
        if a.scan:
            do_scan(mode, cidrs=a.cidr, deep=a.deep, online=not a.offline, sources=a.source,
                    use_shared=not a.no_shared, quick=a.quick, budget=90 if a.quick else None)
        if a.diagnose:
            diagnose()
        if a.share:
            share_ips()
        if a.export is not None:
            export_ips(a.export)
        if a.test:
            do_test()
        if a.fix:
            ok = do_fix(mode, not a.no_scan, cidrs=a.cidr, path=path, verify_after=not path,
                      online=not a.offline, deep=a.deep, sources=a.source,
                      use_shared=not a.no_shared)
            print("完成。" if ok else "未能完成修复。")
    except PermissionError:
        print("❌ 没有写入 hosts 的权限（请用管理员运行 / 检查杀毒软件拦截）。")
    finally:
        if a.elevated:
            input("按回车键退出…")


if __name__ == "__main__":
    main()
