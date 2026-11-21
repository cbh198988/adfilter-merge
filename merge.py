#!/usr/bin/env python3
"""把多个广告过滤列表合并、规范化、去重，输出统一的 DNS 规则文件。

用法：
    python3 merge.py                # 默认输出到 ./dist
    python3 merge.py --out dist     # 指定输出目录
    python3 merge.py --collapse     # 额外做父子域折叠（体积更小，但拦截更激进）
    python3 merge.py --keep-modifiers   # 保留带 $ 修饰符的原始规则（给 AdGuard 客户端用）

输出：
    dist/merged-dns.txt     ABP/AdGuard DNS 规则（||domain^），适合 AdGuard Home、AdGuard 客户端
    dist/merged-hosts.txt   hosts 格式（0.0.0.0 domain），适合 AdAway、路由器、DNSMasq
    dist/stats.md           本次合并的统计报告
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

UA = "Mozilla/5.0 (compatible; adfilter-merge/1.0; +https://github.com)"
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
NULL_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0"}
STRIP_MODIFIERS = False  # 是否把 ||x^$third-party 剥成 ||x^（会扩大拦截范围）


def fetch(urls: list[str], timeout: int = 40, retries: int = 2) -> tuple[str, str]:
    """依次尝试候选 URL，返回第一个成功的内容和实际使用的 URL。"""
    last_err: Exception | None = None
    for url in urls:
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    if resp.headers.get("Content-Encoding") == "gzip":
                        raw = gzip.decompress(raw)
                    text = raw.decode("utf-8-sig", "ignore")
                if len(text.strip()) < 10:
                    raise ValueError("响应内容过短，疑似被拦截")
                return text, url
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if attempt + 1 < retries:
                    time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"全部候选地址都失败：{last_err}")


def parse(text: str) -> tuple[set[str], set[str], dict[str, int]]:
    """解析一个列表，返回 (拦截域名, 放行域名, 分类统计)。

    只保留 DNS 层真正生效的规则：
      - ||domain^            可用
      - 0.0.0.0 domain       hosts 格式，转为域名
      - @@||domain^          例外，单独收集
    丢弃：URL 路径规则、元素隐藏、正则、通配、$ 修饰符、非零 IP 的 hosts 行。
    """
    block: set[str] = set()
    allow: set[str] = set()
    st = dict(
        lines=0, parsed=0, hosts=0, abp=0, exception=0,
        path=0, cosmetic=0, modifier=0, wildcard=0,
        nonzero_ip=0, invalid=0,
    )

    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line[0] in "!#[":
            continue
        st["lines"] += 1

        is_exc = line.startswith("@@")
        if is_exc:
            line = line[2:]

        # 元素隐藏 / 脚本注入类规则
        if any(tok in line for tok in ("##", "#@#", "#?#", "#$#")):
            st["cosmetic"] += 1
            continue

        if line.startswith("||"):
            body = line[2:]
            if "$" in body:
                st["modifier"] += 1
                if not STRIP_MODIFIERS:
                    continue  # DNS 层用不上修饰符，默认整条跳过
                body = body.partition("$")[0]
            if "/" in body:
                st["path"] += 1
                continue
            dom = body.split("^")[0].strip(".").lower()
            if "*" in dom or "?" in dom:
                st["wildcard"] += 1
                continue
            if not DOMAIN_RE.match(dom) or IPV4_RE.match(dom):
                st["invalid"] += 1
                continue
            st["abp"] += 1
            (allow if is_exc else block).add(dom)
            continue

        # hosts 格式：IP domain [domain...]
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            is_ip_line = IPV4_RE.match(ip) or ":" in ip
            if not is_ip_line:
                st["invalid"] += 1
                continue
            if ip not in NULL_IPS:
                # 指向真实 IP 的 hosts 行是重写而不是拦截，丢弃
                st["nonzero_ip"] += 1
                continue
            doms = []
            for d in parts[1:]:
                d = d.strip(".").lower()
                if DOMAIN_RE.match(d) and not IPV4_RE.match(d):
                    doms.append(d)
            if not doms:
                st["invalid"] += 1
                continue
            st["hosts"] += 1
            for d in doms:
                (allow if is_exc else block).add(d)
            continue

        # 单列域名（少数列表这么写）
        dom = line.strip(".").lower()
        if DOMAIN_RE.match(dom) and not IPV4_RE.match(dom):
            st["hosts"] += 1
            (allow if is_exc else block).add(dom)
        else:
            st["invalid"] += 1

    st["exception"] = len(allow)
    return block, allow, st


def collapse_subdomains(domains: set[str], allowed: set[str]) -> set[str]:
    """若父域已在拦截集合中，则丢弃其子域（DNS 层 ||a.com^ 已覆盖 *.a.com）。"""
    out: set[str] = set()
    for d in domains:
        parts = d.split(".")
        redundant = False
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in domains or parent in allowed:
                redundant = True
                break
        if not redundant:
            out.add(d)
    return out


def write_outputs(
    out_dir: str,
    block: set[str],
    allow: set[str],
    rows: list[dict],
    collapse: bool,
) -> None:
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    header = [
        "! Title: 合并去重广告规则 (merged from %d sources)" % len(rows),
        "! Generated: %s" % now,
        "! Blocked domains: %d" % len(block),
        "! Exceptions: %d" % len(allow),
        "! Sources:",
    ]
    for r in rows:
        header.append("!   - %s (%d rules)" % (r["name"], r["parsed"]))

    with open(os.path.join(out_dir, "merged-dns.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n\n")
        if allow:
            f.write("! ==== 放行（白名单）====\n")
            for d in sorted(allow):
                f.write("@@" + "||" + d + "^\n")
            f.write("\n")
        f.write("! ==== 拦截 ====\n")
        for d in sorted(block):
            f.write("||" + d + "^\n")

    with open(os.path.join(out_dir, "merged-hosts.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Title: merged ads hosts (%d domains)\n" % len(block))
        f.write("# Generated: %s\n" % now)
        for d in sorted(block):
            f.write("0.0.0.0 " + d + "\n")

    lines = [
        "# 合并统计",
        "",
        "生成时间：%s" % now,
        "父子域折叠：%s" % ("开启" if collapse else "关闭"),
        "",
        "| 源 | 读取行数 | 有效规则 | 新增独有 | 其中 hosts | 其中 || | 例外 | 丢弃:路径 | 丢弃:修饰符 | 丢弃:非零IP |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            "| {name} | {lines} | {parsed} | {added} | {hosts} | {abp} | {exception} | {path} | {modifier} | {nonzero_ip} |".format(**r)
        )
    lines += [
        "",
        "**合并结果**：拦截 %d 个域名，放行 %d 个，输出文件 merged-dns.txt / merged-hosts.txt。"
        % (len(block), len(allow)),
        "",
    ]
    with open(os.path.join(out_dir, "stats.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sources.json")
    ap.add_argument("--out", default="dist")
    ap.add_argument("--collapse", action="store_true", help="父子域折叠（体积更小）")
    ap.add_argument(
        "--strip-modifiers",
        action="store_true",
        help="把 ||x^$third-party 之类的规则剥掉修饰符后保留域名（更激进）",
    )
    args = ap.parse_args()

    global STRIP_MODIFIERS
    STRIP_MODIFIERS = args.strip_modifiers

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)

    all_block: set[str] = set()
    all_allow: set[str] = set()
    rows: list[dict] = []

    for src in cfg["sources"]:
        name = src["name"]
        try:
            text, used = fetch(src["urls"])
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {exc}", file=sys.stderr)
            rows.append(
                dict(name=name, lines=0, parsed=0, added=0, hosts=0, abp=0,
                     exception=0, path=0, modifier=0, nonzero_ip=0, failed=True)
            )
            continue

        block, allow, st = parse(text)
        before = len(all_block)
        for d in allow:
            all_allow.add(d)
        for d in block:
            all_block.add(d)
        st["name"] = name
        st["parsed"] = len(block)
        st["added"] = len(all_block) - before
        rows.append(st)
        print(f"[OK] {name}: {st['parsed']} 条有效规则（+{st['added']} 新增），来源 {used}")

    # 例外优先：被放行的域名从拦截集合中移除
    all_block -= all_allow

    if args.collapse:
        raw_count = len(all_block)
        all_block = collapse_subdomains(all_block, all_allow)
        print(f"[collapse] {raw_count} -> {len(all_block)} 个域名")

    write_outputs(args.out, all_block, all_allow, rows, args.collapse)
    print(f"完成：拦截 {len(all_block)} 个域名，放行 {len(all_allow)} 个，输出目录 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
