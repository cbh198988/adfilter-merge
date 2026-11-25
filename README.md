# adfilter-merge

把多个广告过滤列表抓下来，**规范化 + 合并 + 按域名去重**，自动发布成订阅链接。  
GitHub Actions 每小时跑一次，上游更新后订阅跟着更新。

**两条订阅完全独立**：主订阅是主体，补充订阅只放主订阅没覆盖的低风险国内 App 广告域名。出问题单独禁用补充订阅即可，主订阅不受影响。

---

## 订阅链接（直接复制到 DNS 过滤器）

### 🟦 主订阅（28,841 条，必用）

```
# 推荐（实时，无缓存，国内网络可用）
https://gh-proxy.com/raw.githubusercontent.com/cbh198988/adfilter-merge/dist/merged-dns.txt

# 备用（CDN，速度快）
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist/merged-dns.txt

# hosts 格式（AdAway / 路由器 / DNSMasq）
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist/merged-hosts.txt
```

### 🟩 补充订阅（470 条，可选，出问题可单独禁用）

```
# 推荐（实时，无缓存）
https://gh-proxy.com/raw.githubusercontent.com/cbh198988/adfilter-merge/dist-extra/merged-extra.txt

# 备用（CDN，速度快）
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist-extra/merged-extra.txt

# hosts 格式
https://cdn.jsdelivr.net/gh/cbh198988/adfilter-merge@dist-extra/merged-extra-hosts.txt
```

> 补充订阅与主订阅**零重复**。若发现误拦，只需在 DNS 过滤器里删掉补充订阅这一条，主订阅照常工作。

---

## 内容与来源

### 主订阅的 5 个源

| 源                                                                          | 格式                | 实测规则数  |
| -------------------------------------------------------------------------- | ----------------- | ------ |
| [10007\_auto `all`](https://github.com/lingeringsound/10007_auto)          | hosts             | 12,427 |
| [AD886 `dnslist.txt`](https://github.com/qq5460168/AD886)                  | ABP `\|\|domain^` | 17,301 |
| [abclq `adguard-dns-full.txt`](https://github.com/abclq/home-dns-adblock)  | ABP               | 1,019  |
| [miaoermua `rule.txt`](https://github.com/miaoermua/AdguardFilter)         | ABP + 例外          | 269    |
| [DickaHandsome `MyRule.txt`](https://github.com/DickaHandsome/My-Ads-Rule) | ABP + 例外          | 449    |

去重后实测 **28,841 个域名**。

### 补充订阅的 7 个源

| 源                   | 说明                        |
| ------------------- | ------------------------- |
| 10007_auto `reward` | 激励视频广告域名（同源不同文件，主订阅漏掉的部分） |
| adguard-cn-filter   | 专门针对中国 App 的 DNS 过滤       |
| ad-wars（大圣净化）       | 国内视频 + App 广告             |
| AWAvenue 秋风规则       | 专注国产 App 开屏广告             |
| yhosts 字节/腾讯/联盟分表   | 广告联盟 SDK 域名               |

生成时先抓取主订阅作为排除集，只输出主订阅没有的纯增量，并经过白名单过滤（放行风控/业务 API/正片 CDN）和大厂裸域保护。去重后 **470 个域名**。

---

## 更新机制

- 主订阅：`cron: "17 * * * *"`，每小时跑一次，产出到 `dist` 分支。
- 补充订阅：`cron: "42 * * * *"`，每小时跑一次，产出到 `dist-extra` 分支。
- 两套 workflow 各自独立，一个失败不影响另一个。
- GitHub 免费 runner 排队常延迟 5~20 分钟，不是故障。
- 产物用 orphan 分支 + force push 发布，每次只保留一个提交，仓库不会因每小时提交而膨胀。

## 内置的两道保护

1. **源站异常不覆盖**：主订阅合并结果少于 1000 条或比上一版减少超过 30%，workflow 直接失败；补充订阅少于 50 条或超过 5000 条同样拒绝发布。
2. **误杀防护**：白名单 `allowlist.txt` 强制放行风控、业务 API、H5 离线包、正片 CDN 等域名；补充订阅额外剔除大厂裸域。
