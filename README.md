# adfilter-merge

把 5 个广告过滤列表抓下来，**规范化 + 合并 + 按域名去重**，自动发布成一个订阅链接。
由 GitHub Actions 每小时跑一次，源列表更新后，合并结果跟着更新。

## 合并的 5 个源

| 源 | 格式 | 实测规则数 |
|---|---|---|
| [10007_auto `all`](https://github.com/lingeringsound/10007_auto) | hosts | 12,427 |
| [AD886 `dnslist.txt`](https://github.com/qq5460168/AD886) | ABP `\|\|domain^` | 17,301 |
| [abclq `adguard-dns-full.txt`](https://github.com/abclq/home-dns-adblock) | ABP | 1,019 |
| [miaoermua `rule.txt`](https://github.com/miaoermua/AdguardFilter) | ABP + 例外 | 269 |
| [DickaHandsome `MyRule.txt`](https://github.com/DickaHandsome/My-Ads-Rule) | ABP + 例外 | 449 |

去重后实测：**28,444 个域名**（其中 3 条白名单例外），输出约 580 KB。

## 部署（3 步）

1. 在 GitHub 新建一个仓库（public 或 private 都行，**private 仓库的 raw 链接需要 token，建议 public**）。
2. 把本目录的全部文件传上去，注意 `.github/workflows/` 目录要一起上传：

   ```bash
   git init
   git add -A
   git commit -m "init"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/<仓库名>.git
   git push -u origin main
   ```

   或者直接用网页的 “Add file → Upload files” 把整个文件夹拖进去（拖拽支持子目录）。
3. 打开仓库的 **Actions** 标签页，若提示 workflow 未启用，点 “I understand my workflows, go ahead and enable them”，然后手动点一次 **Run workflow** 验证。

跑完后会自动创建一个 `dist` 分支，里面是三个产物：

| 文件 | 说明 |
|---|---|
| `merged-dns.txt` | ABP/AdGuard DNS 规则（`\|\|domain^`），**推荐**，AdGuard Home / AdGuard 客户端 / 多数 App 通用 |
| `merged-hosts.txt` | hosts 格式（`0.0.0.0 domain`），给 AdAway、路由器、DNSMasq 用 |
| `stats.md` | 本次每个源贡献了多少规则、丢弃了什么 |

## 订阅链接
推荐（实时，无缓存）
https://gh-proxy.com/raw.githubusercontent.com/cbh198988/adfilter-merge/dist/merged-dns.txt

备用（CDN，速度快）
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist/merged-dns.txt

hosts 格式（AdAway / 路由器）
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist/merged-hosts.txt


把 `<用户名>/<仓库名>` 换成你自己的，三种任选（国内网络建议用后两种）：

```
# 1. GitHub 原始地址（国内常连不上）
https://raw.githubusercontent.com/<用户名>/<仓库名>/dist/merged-dns.txt

# 2. jsDelivr CDN（workflow 里已自动刷新缓存）
https://cdn.jsdelivr.net/gh/<用户名>/<仓库名>@dist/merged-dns.txt

# 3. gh-proxy 加速（和你现在用的方式一致）
https://gh-proxy.com/raw.githubusercontent.com/<用户名>/<仓库名>/dist/merged-dns.txt
```

订阅 hosts 版就把文件名换成 `merged-hosts.txt`。

## 更新机制

- `cron: "17 * * * *"` → **每小时**跑一次，全程约 30~60 秒。
- GitHub 免费 runner 排队常延迟 5~20 分钟，不是故障。
- **重要坑**：仓库连续 60 天没有任何提交/操作，GitHub 会自动暂停定时任务。本 workflow 每小时都会往 `dist` 分支提交，属于仓库活动，正常不会触发；若发现长期没更新，去 Actions 页手动 Run 一次即可恢复。
- 产物用 **orphan 分支 + force push** 发布，每次只保留一个提交，仓库不会因每小时提交而膨胀。

## 内置的两道保护

1. **源站异常不覆盖**：合并结果少于 1000 条，或比上一版减少超过 30%，workflow 直接失败，不会把线上订阅清空。
2. **单个源失败不影响整体**：某个源挂了只会在日志里 `[FAIL]`，其余源照常合并。

## 可选参数

```bash
python3 merge.py --collapse         # 父子域折叠：28,444 -> 21,995（省 23%）
python3 merge.py --strip-modifiers  # 把 ||x^$third-party 剥成 ||x^（拦截更激进，慎用）
```

想启用折叠，把 workflow 里的 `python3 merge.py --out dist` 改成 `python3 merge.py --out dist --collapse`。

## 规则清洗策略

合并时只保留 **DNS 层真正生效** 的规则，下面这些会被丢弃（`stats.md` 里有计数）：

| 丢弃类型 | 原因 |
|---|---|
| `\|\|domain/path` 路径规则 | DNS 层看不到 URL 路径 |
| `$third-party`、`$document`、`$replace` 等修饰符 | DNS 层不支持（`--strip-modifiers` 可改为保留域名） |
| `##` 元素隐藏、`#@#` | 需要浏览器扩展，DNS 层无效 |
| 指向真实 IP 的 hosts 行 | 会变成 DNS 重写，不是拦截 |
| 纯 IP、`localhost`、`ip6-*` | 无效条目 |
| `*-ad.xxx*` 通配 | 支持不稳定，丢弃以免误判 |

`@@||domain^` 例外会被保留，并从拦截集合中剔除（和实际运行时"例外优先"的行为一致）。

## 加源 / 减源

编辑 `sources.json`，按同样结构追加即可，每个源可以给多个候选 URL（依次尝试，第一个成功就用）：

```json
{
  "name": "我的新列表",
  "urls": [
    "https://raw.githubusercontent.com/xxx/yyy/main/list.txt",
    "https://cdn.jsdelivr.net/gh/xxx/yyy@main/list.txt"
  ]
}
```

推送到 main 后 workflow 会自动触发一次。
