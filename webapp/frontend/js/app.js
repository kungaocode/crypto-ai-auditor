// CryptoAudit single-page controller.

import { DEMO_CODE, getJSON, postForm, postJSON } from "./api.js";
import { hydrateIcons } from "./icons.js";
import {
  renderCategoryFilter,
  renderFindingDrawer,
  renderFilterBar,
  renderFindings,
  renderList,
  renderModelCard,
  renderRemediation,
  renderResults,
  renderRules,
  renderRulesStats,
} from "./render.js";
import {
  copyText,
  downloadText,
  escapeHtml,
  formatBytes,
  toast,
} from "./ui.js";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const STAGES = [
  "静态规则扫描（Semgrep / AST / 模式匹配）",
  "微调模型逐条研判",
  "整文件模型独立检测",
  "生成修复代码与报告",
];

const state = {
  health: null,
  rules: [],
  rulesStats: null,
  rulesFilter: { query: "", category: "ALL" },
  rulesIndex: {},
  result: null,
  filters: { severity: "ALL", verdict: "ALL", category: "ALL", query: "" },
  remIndex: 0,
  remMode: "diff",
  inputMode: "paste",
  files: [],
  modelMode: "auto",
  running: false,
};

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

function switchView(name) {
  $$(".nav-item").forEach((button) =>
    button.classList.toggle("is-active", button.dataset.view === name)
  );
  $$("[data-view-panel]").forEach((panel) =>
    panel.classList.toggle("is-active", panel.dataset.viewPanel === name)
  );
  if (name === "results") renderResultsView();
  if (name === "history") loadHistory();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ---------------------------------------------------------------------------
// Health / rules / history
// ---------------------------------------------------------------------------

async function loadHealth() {
  try {
    const data = await getJSON("/api/health");
    state.health = data;
    const staticEngine = data.static_engine || {};
    const engineChip = $("#engine-chip");
    engineChip.innerHTML = staticEngine.semgrep_available
      ? `<span class="dot dot-ok"></span><span>静态引擎就绪</span>`
      : `<span class="dot dot-warn"></span><span>规则引擎降级</span>`;
    engineChip.title = staticEngine.semgrep_available
      ? `Semgrep 可用 · ${staticEngine.rules?.total || 0} 条规则`
      : "未检测到 Semgrep，已启用 AST + 模式匹配兜底";

    const modelChip = $("#model-chip");
    const model = data.model || {};
    modelChip.innerHTML = model.cloud_configured
      ? `<span class="dot dot-ok"></span><span>微调模型可用</span>`
      : `<span class="dot dot-warn"></span><span>离线模式</span>`;
    modelChip.title = model.cloud_configured
      ? `模型 ${model.model_id}`
      : "未检测到 API 密钥，将使用离线确定性引擎";

    const feedbackChip = $("#feedback-chip");
    const feedback = data.feedback || {};
    feedbackChip.innerHTML = feedback.enabled
      ? `<span class="dot dot-ok"></span><span>回流已启用</span>`
      : `<span class="dot dot-warn"></span><span>回流已关闭</span>`;
    feedbackChip.title = feedback.enabled
      ? `待复核样本写入 ${feedback.dataset || "data/webapp_feedback/submissions.jsonl"}`
      : "通过 CRYPTOAUDIT_FEEDBACK=0 关闭源码回流";
    renderModelCard(data);
  } catch (error) {
    toast(`无法读取服务状态：${error.message}`, "err");
  }
}

async function loadRules() {
  try {
    const data = await getJSON("/api/rules");
    state.rules = data.rules || [];
    state.rulesStats = data.stats || {};
    state.rulesIndex = Object.fromEntries(state.rules.map((rule) => [rule.id, rule]));
    renderRulesView();
  } catch (error) {
    $("#rules-list").innerHTML = `<div class="empty-mini">无法加载规则库：${escapeHtml(error.message)}</div>`;
  }
}

function renderRulesView() {
  $("#rules-stats").innerHTML = renderRulesStats(state.rulesStats);
  $("#rules-category-filter").innerHTML = renderCategoryFilter(
    state.rulesStats,
    state.rulesFilter.category
  );
  $("#rules-list").innerHTML = renderRules(state.rules, state.rulesStats, state.rulesFilter);
}

async function loadHistory() {
  try {
    const data = await getJSON("/api/audits");
    $("#history-list").innerHTML = renderList(data.audits || [], "history");
  } catch (error) {
    $("#history-list").innerHTML = `<div class="empty-mini">无法加载历史记录：${escapeHtml(error.message)}</div>`;
  }
}

async function loadRecent() {
  try {
    const data = await getJSON("/api/audits");
    $("#recent-strip").innerHTML = renderList((data.audits || []).slice(0, 4), "recent");
  } catch {
    /* silent: the workbench is still usable without history */
  }
}

async function loadAuditById(auditId) {
  try {
    const data = await getJSON(`/api/audits/${encodeURIComponent(auditId)}`);
    applyResult(data.result);
    switchView("results");
  } catch (error) {
    toast(error.message, "err");
  }
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

function setInputMode(mode) {
  state.inputMode = mode;
  $$("#input-mode .seg").forEach((button) =>
    button.classList.toggle("is-active", button.dataset.mode === mode)
  );
  $$(".input-pane").forEach((pane) =>
    pane.classList.toggle("is-active", pane.dataset.pane === mode)
  );
  updateInputMeta();
}

function updateInputMeta() {
  const meta = $("#input-meta");
  if (state.inputMode === "paste") {
    const lines = $("#code-input").value ? $("#code-input").value.split("\n").length : 0;
    meta.textContent = lines ? `${lines} 行` : "";
  } else {
    meta.textContent = state.files.length ? `${state.files.length} 个文件` : "";
  }
}

function addFiles(fileList) {
  const incoming = Array.from(fileList || []);
  for (const file of incoming) {
    if (!state.files.some((existing) => existing.name === file.name && existing.size === file.size)) {
      state.files.push(file);
    }
  }
  renderFileList();
}

function renderFileList() {
  const list = $("#file-list");
  list.innerHTML = state.files
    .map(
      (file, index) => `
      <li>
        <span class="file-name">${escapeHtml(file.name)}</span>
        <span style="display:flex;align-items:center;gap:8px">
          <span class="file-size">${escapeHtml(formatBytes(file.size))}</span>
          <button class="icon-btn" type="button" data-remove-file="${index}" aria-label="移除文件" style="width:22px;height:22px;font-size:12px">
            <span data-icon="close"></span>
          </button>
        </span>
      </li>`
    )
    .join("");
  hydrateIcons(list);
  updateInputMeta();
}

// ---------------------------------------------------------------------------
// Running an audit
// ---------------------------------------------------------------------------

let overlayTimer = 0;

function showOverlay() {
  const overlay = $("#run-overlay");
  overlay.hidden = false;
  $("#overlay-title").textContent = "正在审计…";
  let index = 0;
  const renderStages = () => {
    $("#overlay-stage").textContent = STAGES[index] || STAGES[STAGES.length - 1];
    $("#overlay-stages").innerHTML = STAGES.map(
      (stage, i) =>
        `<li class="${i < index ? "is-done" : i === index ? "is-active" : ""}">${
          i < index ? "✓ " : i === index ? "› " : ""
        }${escapeHtml(stage)}</li>`
    ).join("");
  };
  renderStages();
  overlayTimer = window.setInterval(() => {
    if (index < STAGES.length - 1) {
      index += 1;
      renderStages();
    }
  }, 2500);
}

function hideOverlay() {
  window.clearInterval(overlayTimer);
  $("#run-overlay").hidden = true;
}

function showRunError(message) {
  const box = $("#run-error");
  box.textContent = message;
  box.hidden = false;
}

async function runAudit() {
  if (state.running) return;
  const errorBox = $("#run-error");
  errorBox.hidden = true;

  const generatePatches = $("#opt-patches").checked;
  const extended = $("#opt-extended").checked;

  let request;
  if (state.inputMode === "paste") {
    const code = $("#code-input").value;
    if (!code.trim()) {
      showRunError("请先粘贴待审计的代码。");
      return;
    }
    request = () =>
      postJSON("/api/audit", {
        code,
        filename: $("#paste-filename").value.trim() || "snippet.py",
        model_mode: state.modelMode,
        generate_patches: generatePatches,
        extended,
      });
  } else {
    if (!state.files.length) {
      showRunError("请先选择至少一个源码文件或压缩包。");
      return;
    }
    request = () => {
      const form = new FormData();
      state.files.forEach((file) => form.append("files", file, file.name));
      form.append("model_mode", state.modelMode);
      form.append("generate_patches", String(generatePatches));
      form.append("extended", String(extended));
      return postForm("/api/audit/upload", form);
    };
  }

  state.running = true;
  $("#btn-run").disabled = true;
  showOverlay();
  try {
    const data = await request();
    if (!data.result) throw new Error("服务端未返回审计结果。");
    applyResult(data.result);
    const feedback = data.result.feedback || {};
    let message = `审计完成，发现 ${data.result.summary?.total_findings || 0} 条候选问题。`;
    if (feedback.error) {
      message += " 回流数据未保存。";
    } else if (feedback.stored_samples) {
      message += ` 已加入 ${feedback.stored_samples} 个待复核训练样本。`;
    }
    toast(message, feedback.error ? "info" : "ok");
    switchView("results");
    loadRecent();
  } catch (error) {
    showRunError(error.message);
    toast(error.message, "err");
  } finally {
    state.running = false;
    $("#btn-run").disabled = false;
    hideOverlay();
  }
}

function applyResult(result) {
  state.result = result;
  state.filters = { severity: "ALL", verdict: "ALL", category: "ALL", query: "" };
  state.remIndex = 0;
  state.remMode = (result.remediation?.files?.[0]?.diff || []).length ? "diff" : "fixed";
  const hasFindings = (result.summary?.total_findings || 0) > 0;
  const navCount = $("#nav-result-count");
  navCount.hidden = !hasFindings;
  navCount.textContent = String(result.summary?.total_findings || 0);
}

// ---------------------------------------------------------------------------
// Rendering the results view
// ---------------------------------------------------------------------------

function renderResultsView() {
  const empty = $("#results-empty");
  const content = $("#results-content");
  if (!state.result) {
    empty.hidden = false;
    content.hidden = true;
    return;
  }
  empty.hidden = true;
  content.hidden = false;
  content.innerHTML = renderResults(state.result, state.rulesIndex);
  hydrateIcons(content);
  renderFindingsInto();
  renderRemediationInto();
}

function renderFindingsInto() {
  if (!state.result) return;
  const filterBar = $("#finding-filter-bar");
  const list = $("#finding-list");
  if (!filterBar || !list) return;
  filterBar.innerHTML = renderFilterBar(state.result.findings || [], state.filters);
  list.innerHTML = renderFindings(state.result.findings || [], state.filters);
  hydrateIcons(filterBar);
  hydrateIcons(list);
  const count = $("#finding-count");
  if (count) count.textContent = `${(state.result.findings || []).filter(matchCurrentFilters).length} 条`;
}

function matchCurrentFilters(finding) {
  const filters = state.filters;
  if (filters.severity !== "ALL" && String(finding.severity).toUpperCase() !== filters.severity) return false;
  if (filters.verdict !== "ALL" && String(finding.verdict).toUpperCase() !== filters.verdict) return false;
  if (filters.category !== "ALL" && finding.category !== filters.category) return false;
  const query = filters.query.trim().toLowerCase();
  if (!query) return true;
  return [finding.rule_id, finding.title, finding.message, finding.cwe, finding.file, finding.category]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

function renderRemediationInto() {
  if (!state.result) return;
  const root = $("#remediation-root");
  if (!root) return;
  root.innerHTML = renderRemediation(
    state.result.remediation,
    state.remIndex,
    state.remMode
  );
  hydrateIcons(root);
}

// ---------------------------------------------------------------------------
// Finding drawer
// ---------------------------------------------------------------------------

function openFinding(fingerprint) {
  const finding = (state.result?.findings || []).find(
    (item) => (item.fingerprint || item.rule_id) === fingerprint
  );
  if (!finding) return;
  $("#drawer-title").textContent = finding.title || finding.rule_id;
  $("#drawer-body").innerHTML = renderFindingDrawer(finding);
  hydrateIcons($("#drawer"));
  $("#drawer").hidden = false;
  $("#drawer-scrim").hidden = false;
}

function closeDrawer() {
  $("#drawer").hidden = true;
  $("#drawer-scrim").hidden = true;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

function reportUrl(format) {
  const id = state.result?.audit_id;
  return `/api/audits/${encodeURIComponent(id)}/report?format=${format}`;
}

async function downloadReport(format) {
  if (!state.result) return;
  try {
    const response = await fetch(reportUrl(format));
    if (!response.ok) throw new Error(`报告生成失败（HTTP ${response.status}）`);
    const text = await response.text();
    const extension = format === "json" ? "json" : "md";
    const mime = format === "json" ? "application/json" : "text/markdown";
    downloadText(`audit-${state.result.audit_id}.${extension}`, text, mime);
    toast("报告已开始下载。", "ok");
  } catch (error) {
    toast(error.message, "err");
  }
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

function bindStaticEvents() {
  $("#topnav").addEventListener("click", (event) => {
    const button = event.target.closest(".nav-item");
    if (button) switchView(button.dataset.view);
  });

  document.addEventListener("click", (event) => {
    const target = event.target;

    const goto = target.closest("[data-goto]");
    if (goto) {
      switchView(goto.dataset.goto);
      return;
    }

    const filter = target.closest("[data-filter-group]");
    if (filter) {
      state.filters[filter.dataset.filterGroup] = filter.dataset.filterValue;
      renderFindingsInto();
      return;
    }

    const findingRow = target.closest("[data-finding]");
    if (findingRow) {
      openFinding(findingRow.dataset.finding);
      return;
    }

    const remFile = target.closest("[data-rem-file]");
    if (remFile) {
      state.remIndex = Number(remFile.dataset.remFile) || 0;
      renderRemediationInto();
      return;
    }

    const remMode = target.closest("[data-rem-mode]");
    if (remMode) {
      state.remMode = remMode.dataset.remMode;
      renderRemediationInto();
      return;
    }

    const copyPatch = target.closest("[data-copy-patch]");
    if (copyPatch) {
      const finding = (state.result?.findings || []).find(
        (item) => (item.fingerprint || item.rule_id) === copyPatch.dataset.copyPatch
      );
      if (finding?.model_patch) copyText(finding.model_patch, "修复片段已复制");
      return;
    }

    const remCopy = target.closest("[data-rem-copy]");
    if (remCopy) {
      const file = state.result?.remediation?.files?.[Number(remCopy.dataset.remCopy)];
      if (file) copyText(file.fixed || "", "修复代码已复制");
      return;
    }

    const remDownload = target.closest("[data-rem-download]");
    if (remDownload) {
      const file = state.result?.remediation?.files?.[Number(remDownload.dataset.remDownload)];
      if (file) downloadText(file.name, file.fixed || "", "text/plain");
      return;
    }

    const auditItem = target.closest("[data-audit-id]");
    if (auditItem) {
      loadAuditById(auditItem.dataset.auditId);
      return;
    }

    const ruleCategory = target.closest("[data-rule-category]");
    if (ruleCategory) {
      state.rulesFilter.category = ruleCategory.dataset.ruleCategory;
      renderRulesView();
      return;
    }

    const removeFile = target.closest("[data-remove-file]");
    if (removeFile) {
      state.files.splice(Number(removeFile.dataset.removeFile), 1);
      renderFileList();
      return;
    }

    const action = target.closest("[data-action]");
    if (action) {
      if (action.dataset.action === "report-md") downloadReport("md");
      if (action.dataset.action === "report-json") downloadReport("json");
      return;
    }

    if (target.closest("#drawer-close") || target.closest("#drawer-scrim")) closeDrawer();
    if (target.closest("#btn-load-sample")) loadSample();
    if (target.closest("#btn-run")) runAudit();
    if (target.closest("#btn-refresh-recent")) loadRecent();
    if (target.closest("#btn-refresh-history")) loadHistory();
  });

  $("#input-mode").addEventListener("click", (event) => {
    const button = event.target.closest(".seg");
    if (button) setInputMode(button.dataset.mode);
  });

  $("#model-mode").addEventListener("click", (event) => {
    const button = event.target.closest(".seg");
    if (!button) return;
    state.modelMode = button.dataset.mode;
    $$("#model-mode .seg").forEach((seg) => {
      const active = seg === button;
      seg.classList.toggle("is-active", active);
      seg.setAttribute("aria-checked", String(active));
    });
    if (state.modelMode === "cloud" && state.health && !state.health.model?.cloud_configured) {
      toast("未检测到 API 密钥，云端模式可能失败；可改用离线引擎。", "info");
    }
  });

  $("#code-input").addEventListener("input", updateInputMeta);
  $("#file-input").addEventListener("change", (event) => addFiles(event.target.files));

  const dropzone = $("#dropzone");
  ["dragenter", "dragover"].forEach((name) =>
    dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.add("is-over");
    })
  );
  ["dragleave", "drop"].forEach((name) =>
    dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.remove("is-over");
    })
  );
  dropzone.addEventListener("drop", (event) => addFiles(event.dataTransfer.files));

  $("#rules-search").addEventListener("input", (event) => {
    state.rulesFilter.query = event.target.value;
    $("#rules-list").innerHTML = renderRules(state.rules, state.rulesStats, state.rulesFilter);
  });

  document.addEventListener("input", (event) => {
    if (event.target.id === "finding-search") {
      state.filters.query = event.target.value;
      const list = $("#finding-list");
      if (list) {
        list.innerHTML = renderFindings(state.result?.findings || [], state.filters);
        hydrateIcons(list);
      }
      const count = $("#finding-count");
      if (count) count.textContent = `${(state.result?.findings || []).filter(matchCurrentFilters).length} 条`;
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
}

function loadSample() {
  setInputMode("paste");
  $("#paste-filename").value = "demo_crypto_vulns.py";
  $("#code-input").value = DEMO_CODE;
  updateInputMeta();
  toast("已载入演示代码，可直接点击「开始审计」。", "info");
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function boot() {
  hydrateIcons(document);
  bindStaticEvents();
  setInputMode("paste");
  loadHealth();
  loadRules();
  loadRecent();
  loadHistory();
}

document.addEventListener("DOMContentLoaded", boot);
