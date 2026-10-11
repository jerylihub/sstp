#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (纯IP直连稳定版)
=====================================
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("WORKER_CHECK_URL", "https://你的域名/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

def log(section, msg=""):
    print(f"========== {section} ==========")
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

def fetch_vpngate():
    try:
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        header_idx = next(i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName"))
        header = lines[header_idx].lstrip("#").split(",")
        data_lines = lines[header_idx + 1:]
        
        ip_idx = next(i for i, h in enumerate(header) if h.strip().lower() == "ip")
        b64_idx = next(i for i, h in enumerate(header) if "base64" in h.lower())
        c_long = next(i for i, h in enumerate(header) if h.strip().lower() == "countrylong")
        c_short = next(i for i, h in enumerate(header) if h.strip().lower() == "countryshort")

        rows = []
        for ln in data_lines:
            fields = next(csv.reader(io.StringIO(ln)))
            if len(fields) <= max(ip_idx, b64_idx, c_long, c_short): continue
            ip = fields[ip_idx].strip()
            if not ip: continue
            rows.append({
                "ip": ip,
                "country_long": fields[c_long].strip(),
                "country_short": fields[c_short].strip(),
                "config_b64": fields[b64_idx].strip(),
            })
        return rows, "vpngate.net"
    except Exception as exc:
        die(f"获取 VPN Gate 数据失败: {exc}")

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                pass
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        
        ip = r["ip"]
        nodes.append({
            "host": ip,
            "port": port,
            "ip": ip,
            "country": r["country_long"],
            "country_code": r["country_short"]
        })
    return nodes

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['ip']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['ip']}:{node['port']}"
    out["success"] = False
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            j = r.json()
            if j.get("success"):
                out["success"] = True
                out["latency_ms"] = j.get("responseTime")
    except Exception:
        pass
    return out

def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    sstp_nodes = to_sstp_nodes(rows)
    
    # 去重
    seen = set()
    uniq = []
    for n in sstp_nodes:
        k = (n["ip"], n["port"])
        if k not in seen:
            seen.add(k)
            uniq.append(n)

    log("CHECK", f"获取到有效 SSTP 节点: {len(uniq)} 个，开始并发检测...")
    
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in uniq]
        for fut in as_completed(futures):
            results.append(fut.result())

    success_nodes = [r for r in results if r.get("success")]
    log("RESULT", f"检测完成，可用节点数: {len(success_nodes)}")

    # 生成 nodes.txt
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    lines = []
    for n in success_nodes:
        code = str(n.get("country_code") or "US").upper()
        zh = COUNTRY_ZH.get(code, code)
        lines.append(f"{zh}#sstp://vpn:vpn@{n['ip']}:{n['port']}")

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    # 生成简单的 data.json 以防 Pages 部署报错
    with open(os.path.join(PUBLIC_DIR, "data.json"), "w", encoding="utf-8") as f:
        json.dump({"success": len(success_nodes), "nodes": success_nodes}, f, ensure_ascii=False)

    log("DONE", f"已生成文件并保存至 {nodes_path}")

if __name__ == "__main__":
    main()
