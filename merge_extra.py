#!/usr/bin/env python3
"""补充规则：只输出【主订阅没有覆盖】的低风险国内 App 广告域名。

设计目标：
  - 与主订阅 merged-dns.txt 完全独立，绝不修改主列表的任何文件/分支。
  - 先抓取主订阅作为排除集，补充规则 = 候选源集合 - 主订阅 - 白名单，零重复。
  - 出问题只需在 DNS 过滤器里禁用这一条补充订阅，主订阅不受任何影响。

输出：
  dist-extra/merged-extra.txt     ABP/AdGuard DNS 规则（||domain^）
  dist-extra/merged-extra-hosts.txt  hosts 格式，方便 hosts 类工具
  dist-extra/extra-stats.md       统计报告

用法：
  python3 merge_extra.py --out dist-extra
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

import merge as m  # 复用主脚本的 fetch / parse / load_allowlist / SAFETY_ALLOW


def load_base_exclusions(urls: list[str], local_path: str | None) -> set[str]:
    """加载主订阅域名作为排除集；优先本地文件，否则从 URL 抓取。"""
    text = None
    if local_path and os.path.exists(local_path):
        with open(local_path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    if text is None:
        text, used = m.fetch(urls)
        print(f"[base] 主订阅排除集来源：{used}")
    base, _allow, _st = m.parse(text)
    # 兜底：直接扫所有 ||domain^ 行，防止主列表格式变化导致漏排除
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("||") and s.endswith("^") and not s.startswith("@@"):
            d = s[2:-1].strip(".").lower()
            if m.DOMAIN_RE.match(d):
                base.add(d)
    return base


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sources-extra.json")
    ap.add_argument("--out", default="dist-extra")
    ap.add_argument("--allowlist", default="allowlist.txt")
    ap.add_argument(
        "--base-urls",
        nargs="+",
        default=[
            "https://gh-proxy.com/raw.githubusercontent.com/cbh198988/adfilter-merge/dist/merged-dns.txt",
            "https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist/merged-dns.txt",
        ],
        help="主订阅地址，用作排除集",
    )
    ap.add_argument("--base-local", default=None, help="本地主订阅文件路径（优先于 URL）")
    args = ap.parse_args()

    import json

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)

    print("[base] 正在加载主订阅排除集 ...")
    try:
        base = load_base_exclusions(args.base_urls, args.base_local)
        print(f"[base] 主订阅共 {len(base)} 个域名（这些不会出现在补充列表里）")
    except Exception as exc:  # noqa: BLE001
        print(f"[FATAL] 无法加载主订阅排除集，拒绝生成（避免与主列表重复）：{exc}", file=sys.stderr)
        return 2

    all_block: set[str] = set()
    all_allow: set[str] = set()
    rows: list[dict] = []

    for src in cfg["sources"]:
        name = src["name"]
        try:
            text, used = m.fetch(src["urls"])
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {exc}", file=sys.stderr)
            rows.append(dict(name=name, added=0, failed=True))
            continue
        block, allow, _st = m.parse(text)
        before = len(all_block)
        all_allow |= allow
        all_block |= block
        added = len(all_block) - before
        rows.append(dict(name=name, added=added))
        print(f"[OK] {name}: 解析 {len(block)} 条（相对其它补充源 +{added}），来源 {used}")

    # 例外优先
    all_block -= all_allow

    # 1) 去掉主订阅已有的（核心：保证零重复）
    overlap = all_block & base
    all_block -= overlap
    print(f"[dedupe] 与主订阅重复 {len(overlap)} 条，已剔除")

    # 2) 外部白名单 + 内置安全白名单（防止把风控/业务/正片域名拦了）
    ext = m.load_allowlist(args.allowlist)
    safe = ext | m.SAFETY_ALLOW
    hit = all_block & safe
    all_block -= safe
    all_allow |= hit
    print(f"[allowlist] 白名单放行 {len(hit)} 条，剩余 {len(all_block)} 条")

    # 3) 兜底：剔除任何大厂裸域（拦裸域会打断整站/整个 App）
    DANGER_BARE = {
        "baidu.com", "qq.com", "tencent.com", "weixin.qq.com", "snssdk.com",
        "bytedance.com", "toutiao.com", "douyin.com", "alipay.com", "taobao.com",
        "tmall.com", "jd.com", "xiaomi.com", "mi.com", "oppo.com", "vivo.com",
        "huawei.com", "honor.com", "ifeng.com", "163.com", "sohu.com", "sina.com",
        "kugou.com", "meituan.com", "bilibili.com",
    }
    hit_bare = all_block & DANGER_BARE
    all_block -= DANGER_BARE
    print(f"[safety] 剔除大厂裸域 {len(hit_bare)} 条")

    # 写入输出
    os.makedirs(args.out, exist_ok=True)
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    header = [
        "! Title: 补充广告规则（主订阅之外的低风险增量）",
        "! Generated: %s" % now,
        "! Blocked domains: %d" % len(all_block),
        "! Note: 本列表与主订阅零重复；出问题单独禁用本订阅即可，主订阅不受影响。",
        "! Sources:",
    ]
    for r in rows:
        header.append("!   - %s (+%s)" % (r["name"], r.get("added", "失败")))

    with open(os.path.join(args.out, "merged-extra.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n\n")
        for d in sorted(all_block):
            f.write("||" + d + "^\n")

    with open(os.path.join(args.out, "merged-extra-hosts.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# 补充广告规则 hosts 格式（%d 个域名）\n" % len(all_block))
        f.write("# Generated: %s\n" % now)
        for d in sorted(all_block):
            f.write("0.0.0.0 " + d + "\n")

    stat_lines = [
        "# 补充规则统计",
        "",
        "生成时间：%s" % now,
        "主订阅域名数（排除集）：%d" % len(base),
        "",
        "| 补充源 | 净新增（相对其它补充源） |",
        "|---|---:|",
    ]
    for r in rows:
        stat_lines.append("| %s | %s |" % (r["name"], r.get("added", "失败")))
    stat_lines += [
        "",
        "- 与主订阅重复剔除：%d" % len(overlap),
        "- 白名单放行：%d" % len(hit),
        "- 大厂裸域剔除：%d" % len(hit_bare),
        "- **最终补充域名：%d**" % len(all_block),
        "",
    ]
    with open(os.path.join(args.out, "extra-stats.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(stat_lines))

    print(f"完成：补充订阅 {len(all_block)} 个域名，输出目录 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
