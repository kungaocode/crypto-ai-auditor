// Pure HTML renderers for each view. Keeps DOM wiring in app.js.

import {
  SEVERITY_LABEL,
  VERDICT_LABEL,
  barRow,
  codeBlock,
  cweTag,
  diffBlock,
  escapeHtml,
  formatBytes,
  formatConfidence,
  formatDate,
  gauge,
  hostOf,
  ruleTag,
  severityBadge,
  topEntries,
  verdictBadge,
} from "./ui.js";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_COLOR = {
  CRITICAL: "#ff4d6d",
  HIGH: "#ff8a3d",
  MEDIUM: "#f5c451",
  LOW: "#4ea1ff",
  INFO: "#8b98a9",
};
const VERDICT_COLOR = { CONFIRMED: "#2dd4bf", UNCERTAIN: "#f5c451", REJECTED: "#8b98a9" };

function severityLabel(key) {
  return SEVERITY_LABEL[key] || key;
}

function languageLabel(value) {
  const label = String(value || "").trim();
  return label.toLowerCase() === "python" ? "Python" : label;
}

function engineBadges(engine) {
  const staticEngine = engine?.static || {};
  const counts = staticEngine.counts || {};
  const out = [];
  out.push(
    `<span class="badge ${staticEngine.semgrep ? "verdict-CONFIRMED" : "sev-INFO"}">Semgrep ${staticEngine.semgrep ? "已启用" : "不可用"}${counts.semgrep != null ? ` · ${counts.semgrep}` : ""}</span>`
  );
  out.push(
    `<span class="badge ${staticEngine.ast ? "verdict-CONFIRMED" : "sev-INFO"}">AST ${staticEngine.ast ? "已启用" : "不可用"}${counts.ast != null ? ` · ${counts.ast}` : ""}</span>`
  );
  out.push(
    `<span class="badge verdict-CONFIRMED">模式匹配${counts.pattern != null ? ` · ${counts.pattern}` : ""}</span>`
  );
  return out.join("");
}

function findingMatches(finding, filters) {
  if (filters.severity !== "ALL" && String(finding.severity).toUpperCase() !== filters.severity) return false;
  if (filters.verdict !== "ALL" && String(finding.verdict).toUpperCase() !== filters.verdict) return false;
  if (filters.category !== "ALL" && finding.category !== filters.category) return false;
  const query = filters.query.trim().toLowerCase();
  if (!query) return true;
  const haystack = [
    finding.rule_id,
    finding.title,
    finding.title_en,
    finding.message,
    finding.cwe,
    finding.file,
    finding.category,
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

export function renderFindings(findings, filters) {
  const list = (findings || []).filter((finding) => findingMatches(finding, filters));
  if (!list.length) {
    return `<div class="empty-mini">没有符合筛选条件的漏洞。</div>`;
  }
  const rows = list
    .map((finding) => {
      return `
        <button class="finding-row" type="button" data-finding="${escapeHtml(finding.fingerprint || finding.rule_id)}">
          ${severityBadge(finding.severity)}
          <span class="f-title">
            <strong>${escapeHtml(finding.title || finding.rule_id)}</strong>
            <span class="f-loc">${escapeHtml(finding.file || "")}${finding.line ? `:${finding.line}` : ""} · ${escapeHtml(finding.message || "")}</span>
          </span>
          <span class="f-cwe">${cweTag(finding.cwe)}</span>
          <span class="f-verdict">${verdictBadge(finding.verdict)}</span>
          <span class="f-conf">${escapeHtml(formatConfidence(finding.confidence))}</span>
          <span class="f-arrow">›</span>
        </button>`;
    })
    .join("");
  return `
    <div class="table-header">
      <span>等级</span><span>漏洞</span><span class="th-cwe">CWE</span>
      <span class="th-verdict">模型结论</span><span>置信度</span><span></span>
    </div>
    <div class="findings-table" id="findings-table">${rows}</div>`;
}

export function renderFilterBar(findings, filters) {
  const severities = ["ALL", ...SEV_ORDER.filter((level) => (findings || []).some((f) => String(f.severity).toUpperCase() === level))];
  const verdicts = ["ALL", ...["CONFIRMED", "UNCERTAIN", "REJECTED"].filter((v) => (findings || []).some((f) => String(f.verdict).toUpperCase() === v))];
  const categories = ["ALL", ...Array.from(new Set((findings || []).map((f) => f.category).filter(Boolean))).sort()];
  const chip = (value, active, label, group) =>
    `<button class="chip${active ? " is-active" : ""}" type="button" data-filter-group="${group}" data-filter-value="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
  return `
    <div class="finding-filters">
      <div class="chip-group">
        ${severities.map((level) => chip(level, filters.severity === level, level === "ALL" ? "全部等级" : severityLabel(level), "severity")).join("")}
      </div>
      <div class="chip-group">
        ${verdicts.map((verdict) => chip(verdict, filters.verdict === verdict, verdict === "ALL" ? "全部结论" : VERDICT_LABEL[verdict] || verdict, "verdict")).join("")}
      </div>
      <div class="chip-group">
        ${categories.map((category) => chip(category, filters.category === category, category === "ALL" ? "全部分类" : category, "category")).join("")}
      </div>
      <label class="search-box">
        <span data-icon="search"></span>
        <input type="search" id="finding-search" placeholder="搜索漏洞 / 文件 / CWE" value="${escapeHtml(filters.query)}">
      </label>
    </div>`;
}

function renderInsights(insights, rulesIndex) {
  const categories = topEntries(insights?.by_category, 6);
  const cwes = topEntries(insights?.by_cwe, 8);
  const rules = topEntries(insights?.by_rule, 6);
  const maxCategory = Math.max(1, ...categories.map(([, value]) => value));
  const maxRule = Math.max(1, ...rules.map(([, value]) => value));

  const categoryBars = categories.length
    ? categories
        .map(([name, value]) =>
          barRow(name, value, maxCategory, "#2dd4bf")
        )
        .join("")
    : `<p class="muted empty-inline">无数据。</p>`;

  const ruleBars = rules.length
    ? rules
        .map(([ruleId, value]) =>
          barRow(rulesIndex?.[ruleId]?.title || ruleId, value, maxRule, "#4c9aff")
        )
        .join("")
    : `<p class="muted empty-inline">无数据。</p>`;

  const cweChips = cwes.length
    ? cwes
        .map(
          ([cwe, value]) =>
            `<span class="badge sev-INFO">${escapeHtml(cwe)} · ${value}</span>`
        )
        .join("")
    : `<span class="muted empty-inline">无数据。</span>`;

  return `
    <div class="insight-columns">
      <div>
        <h4>按漏洞类别</h4>
        <div class="insight-bars">${categoryBars}</div>
      </div>
      <div>
        <h4>高频规则</h4>
        <div class="insight-bars">${ruleBars}</div>
      </div>
      <div>
        <h4>CWE 分布</h4>
        <div class="chip-group">${cweChips}</div>
      </div>
    </div>`;
}

function renderModelDetections(detections) {
  if (!detections || !detections.length) {
    return `<p class="muted empty-inline">本次未执行模型整文件检测。</p>`;
  }
  return `
    <div class="detection-list">
      ${detections
        .map((item) => {
          const vulnerable = item.vulnerable === true;
          const badge = item.vulnerable == null
            ? `<span class="badge sev-INFO">调用失败</span>`
            : vulnerable
              ? `<span class="badge sev-HIGH">存在风险</span>`
              : `<span class="badge verdict-CONFIRMED">未发现</span>`;
          return `
            <div class="detection-item">
              <div class="detection-head">
                <span class="detection-file">${escapeHtml(item.file || "")}</span>
                ${badge}
              </div>
              <div class="muted">${escapeHtml(item.explanation || "无说明")}</div>
              ${item.cwe ? `<div class="cwe-tag">${escapeHtml(item.cwe)}${item.confidence ? ` · 置信度 ${escapeHtml(item.confidence)}` : ""}</div>` : ""}
            </div>`;
        })
        .join("")}
    </div>`;
}

export function renderRemediation(remediation, activeIndex, mode) {
  const files = remediation?.files || [];
  const suggestions = remediation?.suggestions || [];
  if (!files.length) {
    return `
      <div class="panel remediation-wrap">
        <div class="panel-body">
          <div class="empty-mini">没有已确认的漏洞需要修复，或未启用修复代码生成。</div>
        </div>
      </div>`;
  }
  const index = Math.min(Math.max(0, activeIndex), files.length - 1);
  const active = files[index];
  const tabs = files
    .map(
      (file, i) =>
        `<button class="file-tab${i === index ? " is-active" : ""}" type="button" data-rem-file="${i}">${escapeHtml(file.name)}</button>`
    )
    .join("");
  const sourceLabel = active.source === "model" ? "微调模型生成" : active.source === "mechanical" ? "确定性改写" : "仅修复指引";

  let body = "";
  if (mode === "diff") {
    body = diffBlock(active.diff);
  } else if (mode === "original") {
    body = codeBlock(active.original);
  } else {
    body = codeBlock(active.fixed);
  }

  const notes = active.notes && active.notes.length
    ? `<ul class="notes-list">${active.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>`
    : "";

  const changeRows = active.changes && active.changes.length
    ? active.changes
        .map(
          (change) => `
          <div class="change-row">
            <span class="change-rule">${escapeHtml(change.rule_id)}:${escapeHtml(change.line)}</span>
            <span class="change-code">
              <span class="before">- ${escapeHtml(change.before)}</span>
              <span class="after">+ ${escapeHtml(change.after)}</span>
            </span>
          </div>`
        )
        .join("")
    : "";

  const suggestionCards = suggestions.length
    ? `
      <div class="section-title"><h2>修复建议</h2><span class="section-count">${suggestions.length} 条</span></div>
      <div class="suggestions">
        ${suggestions
          .map(
            (item) => `
          <div class="suggestion-card">
            <h4>${ruleTag(item.rule_id)}</h4>
            <p>${escapeHtml(item.summary || "")}</p>
            <div class="code-compare">
              <div class="bad">${escapeHtml(item.bad || "")}</div>
              <div class="good">${escapeHtml(item.good || "")}</div>
            </div>
          </div>`
          )
          .join("")}
      </div>`
    : "";

  return `
    <div class="panel remediation-wrap">
      <div class="rem-toolbar">
        <div class="file-tabs">${tabs}</div>
        <div class="segmented rem-mode">
          <button class="seg${mode === "diff" ? " is-active" : ""}" type="button" data-rem-mode="diff">差异</button>
          <button class="seg${mode === "original" ? " is-active" : ""}" type="button" data-rem-mode="original">原始</button>
          <button class="seg${mode === "fixed" ? " is-active" : ""}" type="button" data-rem-mode="fixed">修复后</button>
        </div>
      </div>
      <div class="panel-body" style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding:10px 14px">
        <span class="muted">${escapeHtml(sourceLabel)}${active.diff?.length ? ` · ${active.diff.length} 行差异` : ""}</span>
        <span style="display:flex;gap:8px">
          <button class="btn btn-ghost btn-sm" type="button" data-rem-copy="${index}">
            <span data-icon="copy"></span><span>复制修复代码</span>
          </button>
          <button class="btn btn-ghost btn-sm" type="button" data-rem-download="${index}">
            <span data-icon="download"></span><span>下载文件</span>
          </button>
        </span>
      </div>
      ${body}
      ${notes}
      ${changeRows ? `<div class="panel-body">${changeRows}</div>` : ""}
    </div>
    ${suggestionCards}
  `;
}

export function renderResults(result, rulesIndex) {
  const target = result.target || {};
  const engine = result.engine || {};
  const model = engine.model || {};
  const feedback = result.feedback || {};
  const summary = result.summary || {};
  const risk = summary.risk || {};
  const severityCounts = risk.severity_counts || {};
  const verdictCounts = risk.verdict_counts || {};
  const findings = result.findings || [];
  const maxSeverity = Math.max(1, ...Object.values(severityCounts));

  const severityBars = SEV_ORDER.filter((level) => severityCounts[level])
    .map((level) => barRow(severityLabel(level), severityCounts[level], maxSeverity, SEV_COLOR[level]))
    .join("") || `<p class="muted empty-inline">未记录到风险项。</p>`;

  const verdictRows = ["CONFIRMED", "UNCERTAIN", "REJECTED"]
    .map(
      (verdict) => `
      <div class="mini-stat">
        <span class="mini-label">${escapeHtml(VERDICT_LABEL[verdict])}</span>
        <span class="mini-value" style="color:${VERDICT_COLOR[verdict]}">${escapeHtml(verdictCounts[verdict] || 0)}</span>
      </div>`
    )
    .join("");

  const modelKind = model.kind === "cloud" ? "微调模型" : "离线引擎";
  const feedbackText = feedback.error
    ? `本次未保存回流样本：${feedback.error}`
    : feedback.enabled
      ? `已保存 ${feedback.stored_samples || 0} 个待复核训练样本至 ${feedback.dataset || "data/webapp_feedback/submissions.jsonl"}`
      : "本次未启用训练数据回流。";
  const feedbackClass = feedback.error ? "dot-bad" : feedback.enabled ? "dot-ok" : "dot-warn";

  return `
    <div class="result-head">
      <div class="result-target">
        <h1>${escapeHtml(target.primary || "审计结果")}</h1>
        <div class="result-meta">
          <span>审计 ID <code>${escapeHtml(result.audit_id)}</code></span>
          <span>${escapeHtml(formatDate(result.created_at))}</span>
          <span>${escapeHtml(target.file_count || 0)} 个文件 · ${escapeHtml(target.line_count || 0)} 行 · ${escapeHtml(formatBytes(target.byte_count || 0))}</span>
          <span>耗时 ${escapeHtml(engine.duration_ms || 0)} ms</span>
        </div>
      </div>
      <div class="result-actions">
        <button class="btn btn-ghost" type="button" data-action="report-md">
          <span data-icon="download"></span><span>Markdown 报告</span>
        </button>
        <button class="btn btn-ghost" type="button" data-action="report-json">
          <span data-icon="download"></span><span>JSON</span>
        </button>
        <button class="btn btn-ghost" type="button" data-goto="audit">
          <span data-icon="terminal"></span><span>再次审计</span>
        </button>
      </div>
    </div>

    <div class="narrative">
      <span data-icon="shield"></span>
      <span>${escapeHtml(summary.narrative || "审计完成。")}</span>
    </div>

    <div class="feedback-banner">
      <span class="dot ${feedbackClass}"></span>
      <span data-icon="layers"></span>
      <span>${escapeHtml(feedbackText)}</span>
    </div>

    <div class="dash-grid">
      <div class="dash-aside">
        <div class="panel score-card">
          ${gauge(risk.score, risk.level)}
          <div class="score-info">
            <h3 style="color:${SEV_COLOR[risk.level] || "#2dd4bf"}">${escapeHtml(risk.label || "—")}</h3>
            <p>共 ${escapeHtml(summary.total_findings || 0)} 条候选问题</p>
            <p>${escapeHtml(modelKind)} · 研判 ${escapeHtml(engine.triaged_findings || 0)} 条</p>
          </div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>模型结论</h2></div>
          <div class="panel-body">${verdictRows}</div>
        </div>
      </div>

      <div class="dash-aside">
        <div class="panel">
          <div class="panel-head">
            <h2>风险等级分布</h2>
            <span class="muted">${escapeHtml(risk.score || 0)}/100</span>
          </div>
          <div class="panel-body"><div class="sev-bars">${severityBars}</div></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>分析引擎</h2></div>
          <div class="panel-body">
            <div class="chip-group" style="margin-bottom:12px">${engineBadges(engine)}</div>
            <div class="mini-stat"><span class="mini-label">模型后端</span><span class="mini-value">${escapeHtml(model.label || modelKind)}</span></div>
            <div class="mini-stat"><span class="mini-label">模型 / 版本</span><span class="mini-value">${escapeHtml(model.model_id || "—")}</span></div>
            <div class="mini-stat"><span class="mini-label">扩展扫描</span><span class="mini-value">${engine.extended ? "已启用" : "标准"}</span></div>
            <div class="mini-stat"><span class="mini-label">整文件模型检测</span><span class="mini-value">${summary.model_detected_vulnerable ? "发现风险" : "未发现"}</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel" style="margin-bottom:16px">
      <div class="panel-head"><h2>模型独立检测</h2><span class="muted">${escapeHtml((summary.model_detections || []).length)} 个文件</span></div>
      <div class="panel-body">${renderModelDetections(summary.model_detections)}</div>
    </div>

    <div class="panel" style="margin-bottom:8px">
      <div class="panel-head"><h2>漏洞分布洞察</h2></div>
      <div class="panel-body">${renderInsights(result.insights, rulesIndex)}</div>
    </div>

    <div class="section-title">
      <h2>漏洞明细</h2>
      <span class="section-count" id="finding-count">${findings.length} 条</span>
    </div>
    <div class="panel">
      <div id="finding-filter-bar"></div>
      <div id="finding-list"></div>
    </div>

    <div class="section-title">
      <h2>修复代码</h2>
      <span class="section-count">${(result.remediation?.files || []).length} 个文件</span>
    </div>
    <div id="remediation-root"></div>
  `;
}

export function renderFindingDrawer(finding) {
  const remediation = finding.remediation || {};
  const context = finding.context_lines && finding.context_lines.length
    ? codeBlock(
        finding.context_lines.map((line) => line.text).join("\n"),
        finding.context_start || (finding.line ? finding.line - 3 : 1),
        finding.line || null
      )
    : codeBlock(finding.context_snippet || finding.snippet || "（无上下文）");

  const advice = remediation.summary
    ? `
      <div class="detail-block">
        <h4>修复建议</h4>
        <div class="callout advice">${escapeHtml(remediation.summary)}</div>
        ${
          remediation.bad || remediation.good
            ? `<div class="advice-grid" style="margin-top:8px">
                <div class="advice-cell bad">${escapeHtml(remediation.bad || "—")}</div>
                <div class="advice-cell good">${escapeHtml(remediation.good || "—")}</div>
              </div>`
            : ""
        }
      </div>`
    : "";

  const modelNote = finding.explanation
    ? `
      <div class="detail-block">
        <h4>${finding.source === "model" ? "模型检测说明" : "模型研判说明"}</h4>
        <div class="callout model">${escapeHtml(finding.explanation)}</div>
      </div>`
    : "";

  const modelPatch = finding.model_patch
    ? `
      <div class="detail-block">
        <h4>模型给出的修复片段</h4>
        ${codeBlock(finding.model_patch)}
        <button class="btn btn-ghost btn-sm" type="button" data-copy-patch="${escapeHtml(finding.fingerprint || "")}" style="margin-top:8px">
          <span data-icon="copy"></span><span>复制片段</span>
        </button>
      </div>`
    : "";

  return `
    <div class="detail-badges">
      ${severityBadge(finding.severity)}
      ${verdictBadge(finding.verdict)}
      ${ruleTag(finding.rule_id)}
      ${cweTag(finding.cwe)}
      <span class="badge sev-INFO">置信度 ${escapeHtml(formatConfidence(finding.confidence))}</span>
    </div>
    <h3 style="font-size:15px;margin-bottom:6px">${escapeHtml(finding.title || finding.rule_id)}</h3>
    <p class="muted" style="margin:0 0 14px">${escapeHtml(finding.message || "")}</p>

    <div class="detail-grid">
      <div class="dg-item"><span class="dg-label">文件</span><span class="dg-value">${escapeHtml(finding.file || "—")}</span></div>
      <div class="dg-item"><span class="dg-label">位置</span><span class="dg-value">${finding.line ? `第 ${escapeHtml(finding.line)} 行` : "整文件"}</span></div>
      <div class="dg-item"><span class="dg-label">类别</span><span class="dg-value">${escapeHtml(finding.category || "—")}</span></div>
      <div class="dg-item"><span class="dg-label">引擎</span><span class="dg-value">${escapeHtml(finding.engine || "—")}</span></div>
      <div class="dg-item"><span class="dg-label">来源</span><span class="dg-value">${escapeHtml(finding.source || "—")}</span></div>
      <div class="dg-item"><span class="dg-label">指纹</span><span class="dg-value" style="font-family:var(--mono);font-size:11px">${escapeHtml(finding.fingerprint || "—")}</span></div>
    </div>

    ${modelNote}

    <div class="detail-block">
      <h4>代码上下文</h4>
      ${context}
    </div>

    ${advice}
    ${modelPatch}
  `;
}

export function renderRules(rules, stats, filter) {
  const query = (filter?.query || "").trim().toLowerCase();
  const category = filter?.category || "ALL";
  const list = (rules || []).filter((rule) => {
    if (category !== "ALL" && rule.category !== category) return false;
    if (!query) return true;
    return [rule.id, rule.title, rule.title_en, rule.cwe, rule.category, rule.message]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });

  if (!list.length) {
    return `<div class="empty-mini">没有匹配的规则。</div>`;
  }

  return list
    .map(
      (rule) => `
      <article class="rule-card">
        <div class="rule-card-head">
          <div>
            <h3>${escapeHtml(rule.title || rule.id)}</h3>
            <span class="rule-en">${escapeHtml(rule.title_en || "")}</span>
          </div>
          ${severityBadge(rule.severity)}
        </div>
        <div class="rule-msg">${escapeHtml(rule.message || "")}</div>
        ${rule.fix ? `<div class="rule-msg"><strong style="color:var(--accent)">修复：</strong>${escapeHtml(rule.fix)}</div>` : ""}
        <div class="rule-foot">
          ${ruleTag(rule.id)}
          ${cweTag(rule.cwe)}
          <span>${escapeHtml(rule.category || "其他")}</span>
          ${(rule.languages || []).map((lang) => `<span class="lang-tag">${escapeHtml(languageLabel(lang))}</span>`).join("")}
        </div>
      </article>`
    )
    .join("");
}

export function renderRulesStats(stats) {
  const bySeverity = stats?.by_severity || {};
  return `
    <div class="stat-card">
      <span class="stat-label">规则总数</span>
      <span class="stat-value">${escapeHtml(stats?.total || 0)}</span>
      <span class="stat-sub">Semgrep + AST 混合检测</span>
    </div>
    <div class="stat-card">
      <span class="stat-label">高危规则</span>
      <span class="stat-value" style="color:var(--high)">${escapeHtml((bySeverity.HIGH || 0) + (bySeverity.CRITICAL || 0))}</span>
      <span class="stat-sub">HIGH / CRITICAL</span>
    </div>
    <div class="stat-card">
      <span class="stat-label">覆盖类别</span>
      <span class="stat-value">${escapeHtml(Object.keys(stats?.by_category || {}).length)}</span>
      <span class="stat-sub">${escapeHtml(Object.keys(stats?.by_category || {}).join(" / ") || "—")}</span>
    </div>`;
}

export function renderCategoryFilter(stats, active) {
  const categories = Object.keys(stats?.by_category || {}).sort();
  const chip = (value, label) =>
    `<button class="chip${active === value ? " is-active" : ""}" type="button" data-rule-category="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
  return [chip("ALL", "全部"), ...categories.map((category) => chip(category, category))].join("");
}

export function renderList(items, kind) {
  if (!items || !items.length) {
    return `<div class="empty-mini">${kind === "history" ? "暂无历史记录，先去审计一段代码吧。" : "暂无记录。"}</div>`;
  }
  return items
    .map((item) => {
      const label = SEVERITY_LABEL[item.level] || item.level || "—";
      const score = Number(item.score) || 0;
      if (kind === "history") {
        return `
          <button class="history-item" type="button" data-audit-id="${escapeHtml(item.audit_id)}">
            <span class="badge sev-${escapeHtml(item.level || "INFO")}">${escapeHtml(label)}</span>
            <span class="h-name">${escapeHtml(item.target || "未命名")}</span>
            <span class="h-files">${escapeHtml(item.file_count || 0)} 个文件</span>
            <span class="h-time">${escapeHtml(formatDate(item.created_at))}</span>
            <span class="h-meta">${escapeHtml(item.total_findings || 0)} 条 · 风险 ${score}</span>
            <span class="h-arrow">›</span>
          </button>`;
      }
      return `
        <button class="recent-item" type="button" data-audit-id="${escapeHtml(item.audit_id)}">
          <span class="recent-top">
            <span class="recent-name">${escapeHtml(item.target || "未命名")}</span>
            <span class="badge sev-${escapeHtml(item.level || "INFO")}">${escapeHtml(label)}</span>
          </span>
          <span class="recent-meta">
            <span>风险 ${score}</span><span>·</span>
            <span>${escapeHtml(item.total_findings || 0)} 条问题</span><span>·</span>
            <span>${escapeHtml(formatDate(item.created_at))}</span>
          </span>
        </button>`;
    })
    .join("");
}

export function renderModelCard(health) {
  const model = health?.model || {};
  const modelId = document.getElementById("model-id");
  const modelUrl = document.getElementById("model-url");
  const modelKey = document.getElementById("model-key");
  if (modelId) modelId.textContent = model.model_id || "—";
  if (modelUrl) modelUrl.textContent = hostOf(model.base_url);
  if (modelKey) modelKey.textContent = model.cloud_configured ? "已配置" : "未配置";
  const dot = document.getElementById("model-card-dot");
  if (dot) dot.className = `dot ${model.cloud_configured ? "dot-ok" : "dot-warn"}`;
}
