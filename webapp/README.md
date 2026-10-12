# CryptoAudit - 密码代码安全审计平台

面向密码学 / 加密相关代码的 AI 辅助安全审计 Web 应用。它把仓库里已有的资产
（`rules/` 下的 Semgrep 规则、`security/audit` 的 AST 扫描器、`model/inference.py`
的微调模型后端）编排成一条完整的审计流水线，并提供一个开箱即用的前端工作台。

当前规则与模型主要面向 Python（`.py` / `.pyw`）；其他语言可以提交，但只会
按现有规则得到有限的扫描结果，不保证获得可靠结论。

流程：**上传代码 -> 静态扫描 + 微调模型研判 -> 漏洞列表 -> 修复建议 / 可直接参考的修复代码 -> 审计报告**。

## 快速开始

```bash
# 在项目根目录执行
./venv/bin/python webapp/run.py --host 127.0.0.1 --port 8770
```

然后浏览器打开 `http://127.0.0.1:8770/`。

依赖（已随仓库 `venv` 安装）：`Flask`、`PyYAML`、`requests`。
静态引擎可选依赖 `semgrep`（不可用时自动降级为内置 AST + 正则扫描器）。

## 功能

- **代码上传 / 粘贴**：推荐提交 `.py` / `.pyw` 源码，也可上传单个源码文件或
  `.zip` 压缩包（自动解包、过滤二进制与超大文件，并限制文件数与总大小）。
- **多引擎协同**：Semgrep 规则 + 内置 AST/正则扫描器做静态检测，再交由微调模型
  对每条发现做研判（确认 / 误报 / 严重度校正），并对整文件做补充检测。
- **修复代码生成**：机械式安全补丁 + 模型生成整文件修复补丁，前端以 diff /
  原始 / 修复三视图展示，可复制或下载。
- **审计结果面板**：风险评分与等级、严重度分布、CWE 分类、发现列表（可筛选、
  搜索）、单条发现的详情抽屉（含上下文代码、证据、修复建议）。
- **规则库浏览**：展示当前 Python 静态规则的标题、分类、CWE、严重度与修复建议。
- **历史记录**：内存中保留最近 30 次审计，可回看结果并重新下载报告。
- **训练数据回流**：默认把每次审计的源码、候选结论和来源元数据写入
  `data/webapp_feedback/submissions.jsonl`，供后续人工复核和再训练。
- **报告导出**：一键导出 Markdown 或 JSON 审计报告。
- **模型模式开关**：`auto` / `cloud（微调模型）` / `mock（离线规则引擎）`，
  以及是否生成补丁、是否开启扩展检测。

## 模型后端与密钥配置

模型通过环境变量配置，密钥只在内存中使用，**不会写盘、不会记入日志、不会通过接口返回**。

| 变量 | 说明 |
| --- | --- |
| `LLM_API_KEY` / `DASHSCOPE_API_KEY` | 云模型 API Key（优先） |
| `LLM_MODEL_ID` | 模型 ID，默认 `qwen3-4b-instruct-2507-5f8261ad123d` |
| `LLM_BASE_URL` | 兼容 OpenAI 的接口地址，默认 DashScope 兼容模式 |
| `LLM_WORKSPACE` | 百炼 workspace 标识（可选） |
| `LLM_TIMEOUT` | 单次请求超时秒数，默认 30 |
| `LLM_API_KEY_FILE` | 从指定文件读取 Key（可选） |
| `CRYPTOAUDIT_READ_API_FILE` | 设为 `0` 可禁止回退读取项目根目录的 `api.txt` |
| `CRYPTOAUDIT_FEEDBACK` | 设为 `0` 可关闭审计源码回流存储 |
| `CRYPTOAUDIT_FEEDBACK_DIR` | 覆盖回流目录，默认 `data/webapp_feedback/` |

模式说明：

- **auto**：仅当显式设置了 `LLM_API_KEY` / `DASHSCOPE_API_KEY` 环境变量时走云模型，
  否则自动使用离线规则引擎，保证无密钥时也能完整演示。
- **cloud**：强制走微调模型；没有可用 Key 时返回明确错误。若仓库根目录存在
  `api.txt`，可作为便利回退来源（受 `CRYPTOAUDIT_READ_API_FILE` 控制）。
- **mock**：始终使用确定性离线规则引擎。

示例：

```bash
export LLM_API_KEY="sk-..."
export LLM_MODEL_ID="qwen3-4b-instruct-2507-5f8261ad123d"
./venv/bin/python webapp/run.py --port 8770
```

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 服务、静态引擎与模型配置状态 |
| GET | `/api/rules` | 静态规则目录与统计 |
| GET | `/api/audits` | 最近审计记录列表 |
| GET | `/api/audits/<id>` | 单次审计完整结果 |
| GET | `/api/audits/<id>/report?format=md\|json` | 下载报告 |
| POST | `/api/audit` | JSON 粘贴代码审计 `{code, filename, model_mode, ...}` |
| POST | `/api/audit/upload` | multipart 上传源码 / `.zip` 至 `files` / `archive` |
| POST | `/api/report` | 用现有结果渲染报告 |
| POST | `/analyze` | 旧版原型兼容接口 |

## 目录结构

```
webapp/
  run.py                  # 启动入口
  backend/
    app.py                # Flask 路由与应用装配
    config.py             # 运行时配置与密钥解析
    service.py            # 审计编排：静态扫描 -> 模型研判 -> 修复
    scanners.py           # Semgrep + AST + 正则静态扫描器
    patches.py            # 机械式安全补丁
    uploads.py            # 粘贴 / 文件 / 压缩包入库与限制
    rules_catalog.py      # 规则目录加载与统计
    feedback.py           # 审计源码回流与待复核训练样本落盘
  frontend/
    index.html            # 单页应用外壳
    style.css             # 深色安全工具主题
    js/                   # api / ui / render / icons / app
```

## 运行测试 / 自检

```bash
./venv/bin/python -m compileall -q webapp
curl -s http://127.0.0.1:8770/api/health
./venv/bin/python -m unittest discover -s webapp/tests -v
```

回流数据默认按源码文件逐行追加到 `data/webapp_feedback/submissions.jsonl`。
记录带有 `verified=false`、`review_status=pending` 和 `training_ready=false`；
模型结论只作为候选标签，经人工复核后才能进入正式训练集。目录与记录格式见
`data/webapp_feedback/README.md`。
