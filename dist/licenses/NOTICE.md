# 来源与许可

生成器代码采用仓库根目录的 GPL-3.0。生成的规则数据保留各自上游的许可与来源，不将本仓库许可证解释为对全部第三方数据重新授权。

- 规则直接来源：[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，精确提交、路径及输入哈希见同一版本的 `sources.lock.json`。其 GPL-3.0 文本取自 master 提交 `4178770badecb1b349fbcd62c737e0d7a2079729`，随包保留。
- MetaCubeX 的 cn 域名集合使用 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 的 ChinaMax_Domain 数据。随包保留该项目在 `4435ba4141d82aab94e541e29023fc6a1f627723` 的 GPL-2.0 文本与原来源说明。本版未再次拼接另一套完整 ChinaMax。
- 其他间接来源以 [MetaCubeX README](https://github.com/MetaCubeX/meta-rules-dat/blob/4178770badecb1b349fbcd62c737e0d7a2079729/README.md) 的致谢及各上游声明为准，包括 domain-list-community、Loyalsoldier 的域名/IP 数据等；上游原作者保留版权。
- 本仓库维护 `overrides/rules.yaml` 中的分类修订，包括国内 AI、Microsoft Copilot 和 Apple 服务例外。平台直连意图参考用户指定的公开 ask-clash 规则快照；未复制其中的私人域名、账号、节点或订阅配置。
- MRS 转换与匹配使用 [chen08209/Clash.Meta](https://github.com/chen08209/Clash.Meta/tree/70f0570405c3c2c47bb113b88db95006d239b346) 固定提交，与当前 AKClash Android 内核来源一致；Go 模块版本和校验值保存在生成器的 go.mod/go.sum。

发布时保留本文件、来源锁及许可证文件。消费者需根据实际采用的数据和代码遵守对应许可。
