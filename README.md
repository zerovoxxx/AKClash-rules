# AKClash-rules

AKClash 的公共规则库，独立于客户端发布。国内 AI 默认直连，海外 AI 和其他代理服务共用唯一的默认节点 `Proxy`。

仓库地址：[zerovoxxx/AKClash-rules](https://github.com/zerovoxxx/AKClash-rules)，Git remote 为 `git@github.com:zerovoxxx/AKClash-rules.git`。

**规则生成器、消费产物和验证已实现。** 推送 `main` 后由 GitHub 工作流检查并发布；可下载版本以仓库的 [Releases](https://github.com/zerovoxxx/AKClash-rules/releases) 为准。Android 的下载、定时检查和运行接入由客户端工程实施。

## 工程目录

生产与消费分成两个目录，仓库根目录只保留说明、许可证和 GitHub 工作流：

```text
AKClash-rules/
├─ README.md
├─ LICENSE                         生成工具的 GPL-3.0 许可证
├─ .github/workflows/rules.yml     验证、每日更新与发布
├─ generator/                     生产加工：只供规则维护者使用
│  ├─ go.mod / go.sum              固定工具链和内核依赖
│  ├─ main.go / rules.go / bundle.go
│  ├─ rules_test.go
│  ├─ sources.yaml                来源、类别和路由顺序
│  ├─ sources.lock.json           固定上游提交、文件大小和 SHA-256
│  ├─ overrides/rules.yaml        人工补充与排除
│  ├─ fixtures/routing.json       预期第一命中和出口
│  ├─ licenses/                   上游许可证及来源说明
│  └─ publish.sh                  完整校验后发布 GitHub Release
└─ dist/                          最终产物：消费方无需运行生成器
   ├─ manifest.json               版本、文件索引、条数、大小和 SHA-256
   ├─ routing.json                有序路由、个人规则和远程集插入位置
   ├─ sources.lock.json           本次产物的来源快照
   ├─ yaml/                      可读的规范化规则
   ├─ mrs/                       可供 mihomo 使用的二进制规则
   └─ licenses/                  随产物分发的来源与许可证
```

本地可放在 AKClash 根目录的 `AKClash-rules/`；它拥有独立 `.git`，父仓库忽略此目录，不是子模块。这个工程无需 Flutter 或 AKClash 应用源码即可构建。

## 分类与来源

| 类别 | 产物 ID | 首版内容 | 默认出口 |
| --- | --- | --- | --- |
| 私有网络 | `private-domain`、`private-ip` | 私有域名与 IPv4/IPv6 | DIRECT |
| 国内 AI | `ai-cn-domain` | 国内 AI 分类，加 Kimi/Moonshot 补充 | DIRECT |
| 海外 AI | `ai-proxy-domain` | OpenAI、Claude、Gemini、Copilot、Grok | Proxy |
| 聊天通信 | `chat-domain`、`chat-ip` | 首版来源为 Telegram 域名与 IPv4/IPv6 | Proxy |
| 通用代理服务 | `proxy-domain` | Google/Play、GitHub、X、YouTube、Netflix、Spotify 与明确的平台代理例外 | Proxy |
| 平台直连 | `platform-direct-domain`、`platform-direct-ip` | Apple/Microsoft 直连域名；Apple 公网 IP | DIRECT |
| 国内网络 | `cn-domain`、`cn-ip` | 国内域名与 IPv4/IPv6 | DIRECT |

按用途分类，具体软件只作为来源，不以 `telegram` 命名公开产物。聊天通信统一归入 chat 类别；域名产物为 `yaml/chat-domain.yaml`，IP 产物为 `yaml/chat-ip.yaml`，对应 `mrs/chat-domain.mrs` 与 `mrs/chat-ip.mrs`。MRS 只支持分别存储 domain 或 ipcidr，因此同一类别保留这两种文件；新增聊天服务可扩充该类别的来源。目前不表示已覆盖所有聊天软件。

产物统一使用 `<类别>-domain.yaml` / `<类别>-ip.yaml`，MRS 使用同名 `.mrs`，清单 ID 与文件名一致。`-ip` 对应 `behavior: ipcidr`，同一文件同时包含 IPv4/IPv6；上游来源 ID 不属于消费接口，继续保留原来源标识。

域名和 IP **可以**写进一个 `behavior: classical` 的 YAML，例如：

```yaml
payload:
  - DOMAIN-SUFFIX,t.me
  - IP-CIDR,149.154.160.0/20
```

但 classical 混合集不能编译成一个 MRS；而且一个 RULE-SET 只有一个外层匹配位置。当前设计中，聊天域名在国内域名前、聊天 IP 在国内域名后，以确保已知国内域名不会因解析到聊天网段而提前代理。简单合并成一个前置 Provider 会改变路由结果。因此继续按类型分包，YAML/MRS 一一对应，不额外维护混合副本；客户端可以将两个文件合并展示为一个“聊天通信”类别。格式依据见 [规则集合内容](https://wiki.metacubex.one/config/rule-providers/content/) 与 [MRS 支持范围](https://wiki.metacubex.one/config/rule-providers/#format)。

类别表达路由意图，数据形态决定文件拆分，不按固定行数切包。上游的共享域名可能跨类别重叠，不能把分类名称当作天然互斥保证；以 `routing.json` 的首次匹配和回归样例决定实际出口。通用代理包不再重复整份聊天来源。

主来源是 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 18 个 YAML 文件。其国内域名包含来自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 的 ChinaMax 数据，首版不再叠加完整 ChinaMax。后续补充来源须明确许可证、类型、最小条数和匹配样例。

国内 AI 使用 `category-ai-cn` 加显式补充；海外 AI 选取五个具体服务集合，不直接采用整个 `category-ai-!cn`。修订包含 Copilot 精确服务补充、移除共享遥测域名及宽泛 CDN 后缀。全部来源和修订见 [sources.yaml](generator/sources.yaml) 与 [overrides/rules.yaml](generator/overrides/rules.yaml)。

公开规则不包含个人 NAS 域名、账号、节点、订阅令牌或用户私有规则。个人规则与用户新增远程集由消费方保存，放入路由定义的对应插入位置；规则库更新不能覆盖它们。

## 如何生产

需要 Go 1.26.2 和 Git。从仓库根目录进入 `generator/` 后执行：

```bash
cd generator
go test -race ./...
go vet ./...
go run . build       # 按 sources.lock.json 固定来源重建 ../dist
go run . check       # 校验现有 ../dist，并验证 YAML/MRS 实际匹配
go run . update      # 解析最新上游提交，验证成功后更新锁文件和 ../dist
bash -n publish.sh
```

`build` 不追踪滚动分支；本地缓存缺失时按固定提交下载并检查哈希。缓存位于 `generator/.cache/`，不进入 Git 或 Release。`update` 对同一仓库/分支只解析一次提交，避免一次构建混用不同快照。

生产流程：

1. 固定来源仓库、提交和路径，验证 HTTPS 下载、大小与内容 SHA-256。
2. 严格解析非空 YAML payload，拒绝非字符串、错误域名/CIDR、混合类型及低于最低条数的输入。
3. 应用补充与排除，规范化、排序和去重，保留精确域名/后缀以及 IPv4/IPv6 语义。
4. 生成可读 YAML，再使用固定内核的转换器编译 MRS。内核依赖与当前 Android 源码基线相同：`chen08209/Clash.Meta@70f0570405c3c2c47bb113b88db95006d239b346`。
5. 分别载入生成的 YAML 和 MRS，以内核匹配能力核对第一命中和目标出口；验证国内/海外 AI、聊天域名/IP、个人及远程例外、平台冲突、局域网、解析后的 IP、IPv6 和最终兜底。
6. 生成 manifest，记录 schema、内核提交、生成器哈希和每个文件的类型、条数、字节数及 SHA-256。全部验证成功后替换 `dist/`；失败保留原产物。

修正规则应编辑来源或修订输入，再重新生成，不手改 `dist/`。新增类别还需要配置其路由位置和匹配样例。格式约束见 [mihomo 规则集合文档](https://wiki.metacubex.one/config/rule-providers/)。

版本号为 `rules-<24 位内容哈希>`，由实际产物、schema、生成器及内核版本决定。固定输入重复生成结果相同。仅上游提交推进、所选规则内容不变时不另发新版本；已发布版本保留发布时的来源锁。复现某个 Release 时，使用该标签的生成代码和 Release 随附的 `sources.lock.json`，将锁文件放回 `generator/` 后执行 `build`。

## 最终产物如何使用

本地消费只需 `dist/`。`manifest.json` 的 `path` 是相对 `dist/` 的路径，`asset` 是该文件在 GitHub Release 中的名称；Release 资产是平铺的，不能把 `yaml/` 或 `mrs/` 目录拼入下载 URL。

现有 mihomo 配置可直接引用下载好的文件，例如：

```yaml
rule-providers:
  chat-domain:
    type: file
    behavior: domain
    format: mrs
    path: ./dist/mrs/chat-domain.mrs
  chat-ip:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./dist/mrs/chat-ip.mrs
rules:
  - RULE-SET,chat-domain,Proxy
  - RULE-SET,chat-ip,Proxy
```

这只是聊天类别的引用示例，需要消费方已有 `Proxy` 节点组；完整顺序见 [dist/routing.json](dist/routing.json)。`routing.json` 是供客户端组装配置的数据契约，不是可直接导入的完整 Clash 配置。YAML 和 MRS 是相同规则的两种表示，消费方选择一种即可。

计划中的 Android 消费方式：

1. 内置稳定入口：`https://github.com/zerovoxxx/AKClash-rules/releases/latest/download/manifest.json`。
2. 读取清单中的 `version` 后，固定从 `https://github.com/zerovoxxx/AKClash-rules/releases/download/<version>/<asset>` 获取该版本所需文件，不逐个追踪 latest。
3. 检查支持的 schema、固定仓库、类型、大小、SHA-256 和路由引用，候选版本全部通过后再切换；失败继续使用随包或上一有效版本。
4. 应用运行时每 24 小时检查，回前台补检查，支持手动刷新。应用关闭时不承诺定时执行。全局规则由应用下载，内核通过 file Provider 读取，避免双重更新。

规则内容及已有类型下的分类调整不需要发布新版 App；新 schema、规则格式或执行能力需要客户端适配。哈希用于完整性检查，不等同于独立的发布者签名。上述 Android 消费流程尚未实现。

## 自动验证与发布

工作流在 PR、main 推送、手动触发时检查；每日 UTC 22:23（北京时间 06:23）尝试更新上游。GitHub 定时任务可能延迟，不是实时更新保证。

检查顺序为测试/静态检查 → 按提交中的锁重建并比对基线 → 非 PR 更新来源 → 再次重建核对一致性 → 上传产物 → 发布。发布脚本还需要 Python 3.9+ 和 GitHub CLI，CI 使用仓库自带的 `GITHUB_TOKEN`。

发布先验证所有文件和哈希，再创建 draft Release；资产全部上传成功后才设为公开和 latest。失败保留 draft，不替换已公开版本；相同内容版本已发布时只校验后退出。发布脚本不会覆盖已公开 Release 的资产。执行结果可在仓库 [Actions](https://github.com/zerovoxxx/AKClash-rules/actions) 查看。

生成器代码按 [GPL-3.0](LICENSE) 分发；规则数据保留各自上游许可和来源，见 [来源与许可说明](generator/licenses/NOTICE.md)。许可证和来源锁随每个规则版本一起交付。
