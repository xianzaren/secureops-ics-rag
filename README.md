# SecureOps — 面向 OT/ICS 网络安全的全栈 RAG 助手

**简体中文** | [English](README_EN.md)

![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=next.js&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

SecureOps 是一个面向工业控制系统（ICS）与运营技术（OT）安全场景的工程化
检索增强生成（RAG）应用。系统从可追溯的 CISA、NIST 和 MITRE 数据源中检索证据，
回答漏洞与安全防护问题，返回明确引用，支持用户文档上传，并提供可复现的真实评估，
而不是手工填写性能数据。

![SecureOps 系统界面](docs/assets/secureops-dashboard.png)

## 项目能力

- 解析 CSAF 2.0 JSON、NIST PDF、MITRE ATT&CK Excel、Vulnrichment CSV
  以及用户上传的 PDF/TXT，并保留来源元数据。
- 扫描完整 CVE 数据，通过可解释的相关性和质量评分保留高价值 OT/ICS 记录。
- 使用 BGE-small 向量检索、BM25 关键词检索、RRF 融合和 Cross-Encoder 重排序。
- 使用 DeepSeek 基于检索证据生成答案，返回稳定的公告、CVE、ATT&CK 和文档引用。
- 提供 FastAPI 普通/流式接口和响应式 Next.js 前端。
- 支持 Docker 持久化卷、健康检查、自动化测试、前端质量检查及 GitHub Actions CI。
- 提供包含 36 个问题的版本化评估集，对比纯向量基线与完整混合检索流水线。

## 系统架构

```text
CISA CSAF ─┐
NIST PDF ──┼─> 来源感知解析 ─> 文本分块 ─┬─> BGE / ChromaDB ─┐
MITRE XLSX ┤                             └─> BM25 ──────────┼─> RRF 融合
CVE CSV ───┤                                                 │
用户文档 ──┘                         查询扩展 ────────────────┘
                                                               ↓
                                                    Cross-Encoder 重排序
                                                               ↓
                                                     有证据约束的 LLM 生成
                                                               ↓
                                                     FastAPI + Next.js UI
```

组件职责、数据流和信任边界详见 [系统架构文档](docs/architecture.md)。

## 知识库

| 数据来源 | 本地快照 | 用途 |
|---|---:|---|
| CISA CSAF 安全公告 | 200 份公告 | 产品、CVE、影响与修复证据 |
| NIST SP 800-82 Rev. 3 | 2023 年 9 月最终版 | OT 架构与安全防护指南 |
| NIST CSF 2.0 | 2024 年 2 月版本 | 网络安全风险治理框架 |
| MITRE ATT&CK for ICS | v19.1 | 战术、技术、缓解措施、资产及关系 |
| CISA Vulnrichment 筛选集 | 119,864 条中的 2,000 条 | 高质量 OT/ICS CVE 补充信息 |

数据来源清单、官方链接及溯源说明见 [doc/SOURCES.md](doc/SOURCES.md)。运行时不依赖
43 MB 的原始 Vulnrichment CSV，仓库直接使用生成后的
`data/processed/cve_high_value.csv`。

### 数据清洗流程

`scripts/prepare_data.py` 会扫描完整原始数据，而不是简单截取前 2,000 行。
记录必须命中明确的工业厂商或 OT/ICS 术语才会进入候选集；随后按照 KEV 状态、
CVSS 严重性、网络可达性、SSVC 决策、字段完整度和时效性排序。最终记录保留
`quality_score` 与 `quality_reasons`，便于审计和解释筛选结果。

当前真实清洗结果：

| 指标 | 结果 |
|---|---:|
| 扫描的原始记录 | 119,864 |
| 去重后的 OT/ICS 候选记录 | 2,700 |
| 最终保留记录 | 2,000 |
| 发布于 2022–2026 年 | 1,981（99.1%） |
| 严重等级为 Critical 或 High | 1,567（78.4%） |
| 平均质量评分 | 63.25 |

完整证据见 [数据质量报告](reports/data_quality_report.md)。

## 使用 Docker 快速启动

前置条件：Docker Desktop 已启动 Linux 容器引擎，并准备好 DeepSeek API Key。
Embedding 和 Reranker 在本地运行，只有最终答案生成会请求配置的 LLM 服务。

```powershell
Copy-Item .env.example .env
# 编辑 .env，填写 DEEPSEEK_API_KEY。不要提交该文件。

docker compose build

# 首次运行：构建适合演示的快速索引。
docker compose run --rm api python scripts/build_index.py --quick

docker compose up -d
docker compose ps
```

浏览器访问 <http://localhost:3000>，API 文档位于 <http://localhost:8000/docs>。

如需索引完整 NIST 文档，请移除 `--quick`：

```powershell
docker compose run --rm api python scripts/build_index.py
```

`rag-index` Docker 卷会持久化 ChromaDB 与 BM25 数据。重新构建镜像不会删除该卷；
修改数据源或分块逻辑后，需要主动重建索引。

## 本地开发

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/build_index.py --quick
uvicorn src.api:app --reload --port 8000
```

在第二个终端启动前端：

```powershell
Set-Location frontend
npm ci
npm run dev
```

也可以通过 `python src/cli.py` 使用交互式命令行客户端。

## API 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 存活检查 |
| `GET` | `/api/status` | 检查索引、生成器、CVE 和 ATT&CK 数据状态 |
| `POST` | `/api/ask` | 返回包含引用和扩展查询的 JSON 答案 |
| `POST` | `/api/ask_stream` | 流式生成答案 |
| `POST` | `/api/upload` | 校验 PDF/TXT 文件并重建索引 |

调用示例：

```powershell
$body = @{ query = "What does ATT&CK technique T0830 describe?" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/ask `
  -ContentType 'application/json' -Body $body
```

## 真实评估

评估程序将检索性能与可选的付费 LLM 生成评估分开执行。检索部分对纯向量基线和
完整混合检索流水线分别计算 Hit@10、MRR@10、nDCG@10、上下文关键词覆盖率、
平均延迟及 P95 延迟。CISA 与 MITRE 问题优先使用精确标识符作为标签；不可回答问题
不参与检索得分，只用于带 LLM 的诚实拒答测试。

基于 8,403 个文本块的 CPU 实测结果：

| 指标 | 纯向量基线 | 混合检索 | 变化 |
|---|---:|---:|---:|
| Hit@10 | 0.8125 | 0.9375 | +0.1250 |
| MRR@10 | 0.7396 | 0.8229 | +0.0833 |
| nDCG@10 | 0.7795 | 0.8789 | +0.0994 |
| 必需来源覆盖率@10 | 0.9219 | 0.9688 | +0.0469 |
| 平均延迟 | 31.46 ms | 1,143.89 ms | +1,112.43 ms |

跨文档 Hit@10 采用严格定义：所有要求的数据源都必须出现在前 10 个结果中。
当前跨文档得分为 0.50，这是项目明确保留的下一阶段优化目标。

```powershell
# 真实检索评估，不调用 LLM API。
docker compose run --rm api python -m src.evaluate

# 可选：同时评估答案生成和诚实拒答。
docker compose run --rm api python -m src.evaluate --with-generation
```

评估产物：

- [Markdown 评估报告](reports/evaluation_report.md)：适合直接审阅。
- `reports/evaluation_report.json`：运行配置和逐问题证据。
- [版本化评估集](data/evaluation_qa.json)：36 条评估数据及真实标签。

## 测试与持续集成

```powershell
pytest -q
Set-Location frontend
npm run lint
npm run build
```

GitHub Actions 会在 push 和 pull request 时执行相同的后端、前端质量门禁。

## 项目结构

```text
.
├── src/
│   ├── ingestion/        # CSAF、PDF、CSV、ATT&CK 及上传文件解析器
│   ├── api.py            # FastAPI 应用
│   ├── indexing.py       # ChromaDB + BM25 索引生命周期
│   ├── retrieval.py      # 向量/关键词/RRF/重排序流水线
│   ├── generation.py     # 有证据约束的生成与引用
│   └── evaluate.py       # 可复现评估程序
├── scripts/              # 数据、索引及评估命令
├── frontend/             # Next.js 前端
├── data/                 # 处理后数据、上传目录及评估集
├── doc/                  # 权威数据源快照和来源清单
├── docs/                 # 架构和发布文档
├── reports/              # 真实 Markdown/JSON 报告
├── tests/                # 单元测试与集成测试
├── Dockerfile
└── docker-compose.yml
```

## 实际应用场景

- 帮助安全分析人员查询 PLC、SCADA、HMI 等工业设备漏洞与修复信息。
- 根据 NIST 指南辅助分析网络分区、远程访问和事件响应要求。
- 查询 MITRE ATT&CK for ICS 攻击技术、缓解措施及技术关系。
- 将企业安全制度、设备手册和应急预案构建为可追溯的内部知识库。
- 为 SOC 分析流程提供带来源证据的知识检索与报告辅助。

## 可扩展方向

- 接入 NVD、EPSS、CISA KEV、IEC 62443、厂商公告或企业内部数据源。
- 增加 DOCX、HTML、Markdown、网页等解析器及增量索引能力。
- 将 ChromaDB 替换为 Milvus、Qdrant、Weaviate 或 Elasticsearch。
- 增加登录、RBAC、多租户隔离、审计日志、限流及可观测性。
- 对接 SIEM、CMDB、漏洞管理或工单系统，但默认保持只读和人工确认。

## 适用范围与限制

- SecureOps 是安全决策辅助原型，不是漏洞扫描器，也不能替代厂商或 CISA 公告。
- 本地数据快照会随时间过期；投入实际使用前应更新数据并重新运行清洗、索引和评估。
- “检索置信度”是经过转换的重排序信号，不代表答案正确率的校准概率。
- 当前评估集由项目维护且规模有限，适合回归测试，不是通用 OT 安全排行榜。

## 贡献、安全与许可证

欢迎参与贡献，具体流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按照
[SECURITY.md](SECURITY.md) 私下报告，不要直接提交公开 Issue。项目源代码采用
[MIT License](LICENSE)；第三方知识资料保留各自的来源和使用条款，详见
[doc/SOURCES.md](doc/SOURCES.md)。

GitHub 发布步骤见 [docs/GITHUB_PUBLISHING.md](docs/GITHUB_PUBLISHING.md)。

## 简历描述示例

> 设计并实现 SecureOps 工业控制系统安全 RAG 助手，基于 FastAPI、Next.js、
> ChromaDB、BGE、BM25、RRF 和 Cross-Encoder 构建可 Docker 部署的全栈应用；
> 完成 CISA/NIST/MITRE 多源数据解析、可解释 CVE 数据清洗、带引用的 LLM 生成，
> 并建立基于精确标识符的可复现检索评估与 CI 流程。
