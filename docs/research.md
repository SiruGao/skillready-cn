# SkillReady：趋势证据与产品选择

研究日期：2026-10-10。目标用户：中国的个人开发者、AI 实施服务商、开始接入 Agent Skills 的小团队。约束：首版不依赖付费模型 API，不采购服务器或广告，不以星标增长承诺收入。

结论：Skills 和插件的关注度仍在增长，但“再做一个技能目录或安全扫描器”已有大量替代品。SkillReady 选择的假设是：**中文团队需要把技能接入前的检查、待补信息、人工验收和交付报告放在一个短流程里。** 这是待验证的产品判断，不是已经证实的市场空白或爆款预测。

## 一、实时采集口径

本次直接通过 HTTPS 获取 GitHub 官方 Trending 页，解析 `article.Box-row` 中的仓库名、总星标和页面显示的期间新增星标，没有把搜索摘要中的总星标当作增量。

| 数据源 | HTTP Date | 北京时间 | 结果 |
| --- | --- | --- | --- |
| [GitHub Trending / This week](https://github.com/trending?since=weekly) | 2026-10-10 06:29:54 UTC | 2026-10-10 14:29:54 | HTTP 200，11 个仓库 |
| [GitHub Trending / This month](https://github.com/trending?since=monthly) | 2026-10-10 06:29:55 UTC | 2026-10-10 14:29:55 | HTTP 200，22 个仓库 |

“周增量”“月增量”沿用 GitHub 的 `stars this week` / `stars this month` 标签。页面未给出精确起止时刻，因此不把它们写成自算的自然周、自然月或两个日期之间的净增量。Trending 本身也不是按新增星标降序排列的全站榜单。

下表是从两个实时页面选取的 10 个代表项目，覆盖热门方向与本项目的直接相关方向；不是完整榜单。`—` 表示该仓库未出现在本次抓到的相应榜单中，不代表该期间增长为零。总星标与增量全部来自同一轮实时抓取。

| 项目 | 总星标 | GitHub 显示周增量 | GitHub 显示月增量 | 关注点 |
| --- | ---: | ---: | ---: | --- |
| [boykopovar/AnyPS5](https://github.com/boykopovar/AnyPS5) | 23,268 | +15,539 | — | 游戏可执行文件移植；热点不等于适合本项目的商业机会 |
| [mattpocock/skills](https://github.com/mattpocock/skills) | 283,161 | +8,156 | — | 可复用工程技能 |
| [Panniantong/Agent-Reach](https://github.com/Panniantong/Agent-Reach) | 95,094 | +7,084 | — | 给 Agent 接入网络信息来源 |
| [heygen-com/hyperframes](https://github.com/heygen-com/hyperframes) | 59,940 | +4,003 | +11,576 | Agent 可调用的视频制作工具 |
| [cursor/plugins](https://github.com/cursor/plugins) | 10,633 | +1,125 | +3,503 | 插件规格与官方插件 |
| [affaan-m/ECC](https://github.com/affaan-m/ECC) | 276,092 | — | +22,710 | 技能、记忆和 Agent 工程工作流 |
| [alibaba/open-code-review](https://github.com/alibaba/open-code-review) | 45,490 | — | +23,028 | 确定性检查与 Agent 结合的代码审查 |
| [debpalash/VoiceStudio](https://github.com/debpalash/VoiceStudio) | 56,556 | — | +34,560 | 本地语音生产工具 |
| [vectorize-io/hindsight](https://github.com/vectorize-io/hindsight) | 47,804 | — | +24,617 | Agent 记忆 |
| [Tencent/WeKnora](https://github.com/Tencent/WeKnora) | 32,914 | — | +11,118 | 文档知识库、RAG 与 Agent |

证据来源：[实时周榜](https://github.com/trending?since=weekly)、[实时月榜](https://github.com/trending?since=monthly)。这些链接会随时间变化；上表保留的是上述采集时刻的值，不能自动作为未来宣传时的最新数值。

早期搜索工具曾返回抓取时间为 3—4 周前的 Trending 缓存。那些缓存只用于发现项目，**未用于上表的实时增量**。本研究没有取得每一天的完整历史快照，也没有估计星标购买、真实活跃用户或付费用户数量。

## 二、从热度到需求的推断

第一，Skills 供给仍在扩张。工程技能仓库与官方插件仓库同时出现在周榜或月榜，说明可复用能力的分发仍能吸引开发者。但“更多技能”并不能直接证明“团队愿意付费验收技能”。

第二，关注点已经超出聊天界面：记忆、联网、文件处理、视频生成与代码审查都有增长。团队接入的东西越多，越需要回答它来自哪里、要访问什么、依赖什么环境、能交付什么、由谁确认。这是 SkillReady 的需求假设。

第三，适合零外部运行成本的第一步是确定性文件检查和交付资料整理。完整模型评测、动态沙箱、深度恶意代码检测需要不同的技术与运营投入，不能用几条字符串规则宣称已经实现。

## 三、现有竞争：安全和验证都不是空白

以下功能依据项目官方 README / 文档核验。它们是能力对照，不是未经测试的效果排名。

| 项目 | 已有能力 | 对 SkillReady 的约束与机会 |
| --- | --- | --- |
| [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | 模式匹配、AST / 数据流、可选 LLM 分析，以及 CI 接入；作者明确称其为尽力而为的检测 | 不应另造“全面安全扫描”承诺；可把专业扫描结论作为未来验收材料 |
| [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Agent、Skills、MCP、基础设施与越狱评估，并有中文界面和文档 | “中文安全扫描”已经有成熟供给，中文本身不构成护城河 |
| [agent-ecosystem/skill-validator](https://github.com/agent-ecosystem/skill-validator) | 结构、链接、内容、上下文开销检查，可选 LLM 评分，CI 与 Markdown 报告 | 仅检查 frontmatter 或导出报告不足以形成独特价值 |
| [SkillLint](https://github.com/Meet-Miyani/agent-skill-validator/blob/main/README.md) | 浏览器本地导入文件夹 / ZIP / SKILL.md，检查结构、引用、脚本、上下文预算，修复与导出 | “本地、不上传、免服务器”也已有直接竞争；必须验证验收工作流的额外价值 |

因此，SkillReady 的定位应集中在**中文企业接入验收工作流**：整理输入证据、发现缺项、说明检查范围、记录人工判断、形成可交付材料。检查项要区分“格式规则”“启发式提示”“人工确认”；没有发现问题只能表示在已检查范围内未发现，不能输出安全认证或保证。

格式检查的依据应可追溯到 [Agent Skills 官方规范](https://agentskills.io/specification)。例如必填的 `name` / `description` 与可选的 `compatibility` / `license` 要分开处理；团队希望补充负责人、回滚步骤等内容，可以作为自定义验收要求，但不能伪装成官方规范的强制字段。

## 四、产品取舍与收费假设

首版要验证的用户路径是：导入技能资料 → 查看可定位的问题与待补信息 → 补充业务用途、依赖和人工确认 → 导出验收材料。只使用前端静态处理与可审查规则，可以避免每次使用产生模型账单。开发时间、用户支持和免费托管额度仍是真实约束，“零成本”仅指不主动引入付费 API、服务器、域名或广告采购。

潜在客户优先选 AI 实施服务商和正在交付企业 Agent 的小团队：他们可能需要给客户留下接入说明与验收记录。付费候选项是企业自定义检查规则、中文交付模板、已有技能库整理与接入辅导；不能假定免费检查页面本身就有强付费意愿。

验证顺序：

1. 先让真实目标用户用自己的技能走完一次检查和导出，记录他们原本怎么做以及哪一步省时。
2. 区分“觉得有趣”“反复使用”“愿意购买服务”，不把访问量或 GitHub star 作为收入。
3. 在有人明确需要企业规则或交付支持后，以可界定范围的小额服务验证收费；价格、付款方式和履约范围另行确认。
4. 若用户只需要格式校验，优先复用或兼容现有验证器；若用户需要真实安全保证，就需要专业扫描、测试与人工评审，不能扩大现有规则的宣传口径。

当前证据足以支持一个低成本试验，尚不足以预测“下一款必火项目”、收益规模或收益时间。产品发布与真实收款是两个不同里程碑。

## 五、复核说明

实时榜单在匿名 HTTPS 请求下返回 HTTP 200；解析时周榜得到 11 条，月榜得到 22 条，逐项读取期间标签。研究仅获取公开页面，没有安装或执行任何热门项目代码。

用于本轮核对的原始 HTML 内容 SHA-256：

```text
weekly  4594b93ada8e9fef44fdce316abe03d774faaca12e458995a454940b5ab8239e
monthly f4cbdcf95ecc7efe5135ca3b34b1e378396b0740ae390f6edfd7d2f942b46973
```

复查趋势可重新抓取两个官方 Trending 页面。若要复现本表历史值，需要保存对应采集时刻的网页快照；当前动态页面不能证明旧时刻的值。
