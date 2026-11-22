#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
处理“分享可用 IP”的 Issue：提取 IP → 在 GitHub Actions 环境验证 → 合并进 ips.txt。

安全约定：
  * Issue 内容是不可信输入：只提取“长得像 IP 的片段”并用 ipaddress 校验，不执行、也不回显其它任何文本。
  * 只收公网地址；每个 Issue 最多 40 个；ips.txt 最多保留 300 个（新的在前）。
  * 验证 = 对 translate.googleapis.com 做 TLS（校验证书链与域名）+ 请求接口，返回 200 或 429 才算通过。
  * Actions 在境外，可能连不上只有境内网络才能到达的 IP：这类“无法验证”的 IP
    仅当提交者是仓库 OWNER / MEMBER / COLLABORATOR 时才收录。
  * 客户端使用共享库时仍会在本机重新验证每个 IP，所以即使库被投毒，也无法让用户写入假 IP。
"""
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

HOST = "translate.googleapis.com"
PATHS = ["/translate_a/l?client=chrome&hl=en",
         "/translate_a/single?client=gtx&sl=en&tl=zh-CN&dt=t&q=hello"]
MAX_PER_ISSUE, MAX_TOTAL = 40, 300
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
LIST_FILE = "ips.txt"
HEADER = ("# ChromeTranslateFix 共享可用 IP 库（由 Actions 自动维护，新的在前）\n"
          "# 每个 IP 在用户本机使用前都会重新验证；失效 IP 会随新提交被挤出。\n")


def http_status(ip, path, timeout=6.0):
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, 443))
        s = ssl.create_default_context().wrap_socket(s, server_hostname=HOST)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        buf = b""
        while b"\r\n" not in buf and len(buf) < 2048:
            c = s.recv(1024)
            if not c:
                break
            buf += c
        m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", buf)
        return int(m.group(1)) if m else 0
    finally:
        s.close()


def classify(ip):
    """返回 ok / bad / unreachable。"""
    for path in PATHS:
        try:
            code = http_status(ip, path)
        except ssl.SSLError:
            return "bad"                      # 证书不符等：不是翻译服务器
        except OSError:
            return "unreachable"              # 连不上（超时/拒绝/不可达）：Actions 环境无法判断
        except Exception:
            return "bad"
        if code in (200, 429):
            return "ok"
    return "bad"


def extract_ips(text):
    out = []
    for tok in re.findall(r"[0-9A-Fa-f:.]{7,45}", text or ""):
        try:
            a = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if a.is_global:
            out.append(str(a))
    return list(dict.fromkeys(out))[:MAX_PER_ISSUE]


def load_list(path=LIST_FILE):
    items = []
    try:
        for line in open(path, encoding="utf-8"):
            body = line.split("#")[0].strip()
            if not body:
                continue
            try:
                ipaddress.ip_address(body)
            except ValueError:
                continue
            date = line.split("#", 1)[1].strip() if "#" in line else ""
            items.append((body, date))
    except OSError:
        pass
    return items


def main():
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    ips = extract_ips(event.get("issue", {}).get("body") or "")
    trusted = os.environ.get("AUTHOR_ASSOC", "") in TRUSTED
    with ThreadPoolExecutor(10) as ex:
        results = dict(zip(ips, ex.map(classify, ips)))
    accepted = [ip for ip, r in results.items() if r == "ok" or (r == "unreachable" and trusted)]
    today = time.strftime("%Y-%m-%d")
    merged = [(ip, today) for ip in accepted]
    seen = set(accepted)
    for ip, d in load_list():
        if ip not in seen:
            merged.append((ip, d))
            seen.add(ip)
    merged = merged[:MAX_TOTAL]
    with open(LIST_FILE, "w", encoding="utf-8") as f:
        f.write(HEADER)
        for ip, d in merged:
            f.write(f"{ip}  # {d}\n")
    n_ok = sum(1 for r in results.values() if r == "ok")
    n_unr = sum(1 for r in results.values() if r == "unreachable")
    n_bad = sum(1 for r in results.values() if r == "bad")
    note = "" if (trusted or not n_unr) else f"其中 {n_unr} 个在 Actions 环境无法连通（可能仅境内可达），非仓库成员提交时不收录。"
    with open("summary.md", "w", encoding="utf-8") as f:
        f.write(f"感谢分享！共收到 {len(ips)} 个 IP：验证通过 {n_ok} 个，未通过验证 {n_bad} 个，"
                f"无法验证 {n_unr} 个；本次收录 {len(accepted)} 个。{note}\n")
    print(open("summary.md", encoding="utf-8").read())


if __name__ == "__main__":
    main()
