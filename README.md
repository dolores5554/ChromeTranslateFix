# Chrome 翻译一键修复工具

谷歌关闭中国大陆的谷歌翻译服务后，Chrome 内置翻译依赖的 `translate.googleapis.com` 无法直接访问。
本工具通过修改 `hosts`，把相关域名指向**实测可用**的 Google 前端 IP，并在 IP 失效时自动扫描新的可用 IP。

- 图形界面 + 命令行，Windows 为主，macOS / Linux 可用命令行
- **一键修复（默认 IPv4 + IPv6 都修复）**：先测本地库；首次使用或本地库失效时先做约 1 分钟的**快速扫描**建立本地库，再对这些 IP 复测延迟，挑最快最稳的写入 hosts 并真实请求验证；快速扫描没找到才进入耗时更长的**深度扫描**；已修复但缺 IPv4 / IPv6 其中一族时，只针对缺的一族补扫
- IP 扫描（分阶段、可扩展）：内置库 → 在线 IP 库 / DoH 发现 / 官方地址段 → `.90` 规律扫描 → 随机抽样 → 命中 IP 的邻近扩展
- 支持 IPv4 与 IPv6（含公共 NAT64 网关通道，作为备用）
- 默认同时映射 `translate.googleapis.com`、`translate.google.com`、`translate-pa.googleapis.com`、`jnn-pa.googleapis.com`
- 修改前自动备份 hosts（`hosts.gtfix.bak`），只改动自己的标记区块，一键还原
- 稳定性复测（每个 IP 测 3 次）、代理 / TUN 检测、诊断报告

## 使用

### 方式一：下载 exe（推荐）
到 [Releases](../../releases) 下载 `ChromeTranslateFix.exe`，双击运行并同意 UAC 提示，点「一键修复」，完成后**完全退出并重启 Chrome**。

### 方式二：用 Python 运行
需要 Python 3.8+（无第三方依赖）：

```bash
python gtfix.py                 # 图形界面（Windows 会自动请求管理员权限）
python gtfix.py --fix           # 命令行一键修复
sudo python3 gtfix.py --fix     # macOS / Linux
```

### 常用命令行选项
| 选项 | 说明 |
|---|---|
| `--fix` | 一键修复 |
| `--scan` | 仅扫描并列出可用 IP |
| `--test` / `--status` | 测试 / 查看当前状态 |
| `--restore` | 还原 hosts |
| `--set IP [IP...]` | 手动写入指定 IP |
| `--ipv4` / `--ipv6` | 只用某个协议 |
| `--quick` | 快速扫描（约 1 分钟，用于建立本地库） |
| `--deep` | 深度扫描 |
| `--offline` | 不联网扩展（跳过 DoH / 在线库 / 官方地址段） |
| `--cidr 网段` / `--source URL` | 自定义扫描网段 / 在线 IP 库 |
| `--main-host-only` | 只映射 `translate.googleapis.com` |
| `--share` | 分享本机验证过的 IP（打开预填的 GitHub Issue，由你确认提交） |
| `--export [文件]` | 导出本机验证过的 IP（`ips.txt` 格式，维护者可直接粘贴进仓库） |
| `--shared-repo 用户名/仓库名` / `--no-shared` | 指定 / 禁用共享 IP 库 |
| `--diagnose` | 输出诊断报告（提交 issue 时请附上） |

自定义扫描范围也可写入程序旁的 `gtfix_ranges.txt`（每行一个 CIDR 或 IP；以 `http` 开头的行视为在线 IP 库）。

## （可选）共享可用 IP 库

默认**关闭**，不影响一键修复的速度。只有在 `gtfix.py` 顶部设置了 `SHARED_REPO = "用户名/仓库名"`（或运行时加 `--shared-repo`）后才会启用：快速 / 深度扫描会把共享库 `ips.txt` 里的 IP 作为额外候选一起测试。

**分享**：修复成功后，点界面里的「分享可用 IP」（命令行 `--share`），浏览器会打开一个**预填好的 GitHub Issue**，内容只有 IP 列表。你检查后点 Submit 才会提交（需登录 GitHub，提交会公开显示你的账号）。工具本身不保存任何 GitHub 令牌，也不会后台上传。

**收录**：提交 Issue 后，GitHub Actions（`collect-ips.yml`）会自动：提取其中的 IP → 对 `translate.googleapis.com` 做 TLS 证书校验并请求接口 → 通过的合并进 `ips.txt`（新的在前，最多 300 个）→ 回复并关闭 Issue。

**安全模型**：
- 共享库是**不可信数据**。客户端对每个 IP 都会在本机重新做证书校验和接口探测，通过才会写入 hosts；Issue 内容里除 IP 格式的片段外一律忽略。因此即使有人恶意提交，也只会让大家多浪费几次探测，无法让用户写入假的 IP。
- Actions 运行在境外，可能连不上只有境内网络才能到达的 IP：这类“无法验证”的 IP 仅当提交者是仓库 OWNER / MEMBER / COLLABORATOR 时才收录。
- jsDelivr 对分支内容有缓存（最长约 12 小时），新收录的 IP 可能稍后才对所有人可见；客户端会回退到 GitHub raw。

**仓库维护者需要做的**：
1. 开启仓库的 Issues。
2. Settings → Actions → General → Workflow permissions 选择 **Read and write permissions**。
3. 打包前在 `gtfix.py` 顶部手动设置 `SHARED_REPO = "用户名/仓库名"`（或运行时加 `--shared-repo`）。
4. `ips.txt` 里的初始条目只是种子，可以自己用 `--export` 导出后更新。

## 自己打包 exe
- 本机：安装 Python 后双击 `build_exe.bat`
- 云端：给仓库打 tag（如 `v1.0.0`），GitHub Actions 会自动打包并发布到 Releases；也可在 Actions 页面手动运行 `build-exe`

## 常见问题
- **首次使用为什么要等约 1 分钟？** 本地库还是空的，需要先快速扫描建库；之后再运行会直接测试本地库，几秒内完成。本地库保存在程序旁的 `gtfix_ips.json`，已失效的 IP 会自动清理。
- **只修复了 IPv4？** 很多网络的 IPv6 没有境外出口。IPv6 近期扫不到时，24 小时内的一键修复会先跳过 IPv6；选择「仅 IPv6」可强制重试。
- **所有 IP 都超时 / TCP 不通**：先完全关闭代理与 TUN（Clash 的 fake-ip / TUN 会让探测失真），或换网络再试。
- **日志里的 `限流429`**：表示连到了真正的 Google 翻译前端，只是对探测请求限流，这类 IP 可用。
- **`HTTP 404`**：连到的是不提供翻译接口的节点（例如境内的 Google 节点），不会被采用。
- **IPv6 不通**：很多网络的 IPv6 没有境外出口；IPv4 可用时无需 IPv6，可选择「仅 IPv4」。
- **杀毒软件拦截 / 误报**：修改 hosts 可能被拦截，请放行；自行打包的 exe 没有数字签名，可能被误报。
- IP 会随时间失效，本工具的价值在于失效后能自动重新扫描。

## 说明与免责
- 本工具只修改你本机的 hosts 文件，不安装驱动、不常驻后台；还原后即恢复原状。
- 请遵守所在地法律法规及 Google 的相关服务条款，使用风险自负。
- NAT64 备用通道使用的是志愿者提供的公共网关（见 [nat64.xyz](https://nat64.xyz)），请勿高频反复扫描；网关能看到目标 IP 与 SNI，看不到加密内容。
- 本项目按「现状」提供，不附带任何担保。

## 致谢
思路与 IP 收集参考了社区项目：
[hcfyapp/google-translate-cn-ip](https://github.com/hcfyapp/google-translate-cn-ip)、
[GoodCoder666/GoogleTranslate_IPFinder](https://github.com/GoodCoder666/GoogleTranslate_IPFinder)、
[Ponderfly/GoogleTranslateIpCheck](https://github.com/Ponderfly/GoogleTranslateIpCheck)。

## 许可
MIT，见 [LICENSE](LICENSE)。
