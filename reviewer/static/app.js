const VERDICTS = {
  confirm: { name: "确认漏洞" },
  reject: { name: "判定误报" },
};

const state = {
  session: null,
  filter: "unlabeled",
  currentId: null,
  loadedId: null,
  recentIds: [],
  pendingAction: null,
  busy: false,
  exportMessage: "",
};

const elements = {
  reviewerChip: document.getElementById("reviewer-chip"),
  topProgress: document.getElementById("top-progress"),
  progressFill: document.getElementById("progress-fill"),
  queuePosition: document.getElementById("queue-position"),
  statusDot: document.getElementById("status-dot"),
  itemStatus: document.getElementById("item-status"),
  reviewPanel: document.getElementById("review-panel"),
  packageName: document.getElementById("package-name"),
  itemCwe: document.getElementById("item-cwe"),
  itemAdvisory: document.getElementById("item-advisory"),
  itemCve: document.getElementById("item-cve"),
  verdictBadge: document.getElementById("verdict-badge"),
  modelAuditStrip: document.getElementById("model-audit-strip"),
  modelAuditDecision: document.getElementById("model-audit-decision"),
  modelAuditConfidence: document.getElementById("model-audit-confidence"),
  modelAuditExplanation: document.getElementById("model-audit-explanation"),
  modelAuditDetail: document.getElementById("model-audit-detail"),
  repoLink: document.getElementById("repo-link"),
  filePath: document.getElementById("file-path"),
  fixCommitLink: document.getElementById("fix-commit-link"),
  notificationLink: document.getElementById("notification-link"),
  vulnCodeLink: document.getElementById("vuln-code-link"),
  fixedCodeLink: document.getElementById("fixed-code-link"),
  codeVuln: document.getElementById("code-vuln"),
  codeFixed: document.getElementById("code-fixed"),
  ruleSelect: document.getElementById("rule-select"),
  severitySelect: document.getElementById("severity-select"),
  splitSelect: document.getElementById("split-select"),
  explanationInput: document.getElementById("explanation-input"),
  findingInput: document.getElementById("finding-input"),
  noteInput: document.getElementById("note-input"),
  verdictButtons: [...document.querySelectorAll(".verdict-button")],
  filterButtons: [...document.querySelectorAll("[data-filter]")],
  prevButton: document.getElementById("prev-button"),
  nextButton: document.getElementById("next-button"),
  clearButton: document.getElementById("clear-button"),
  reviewedCount: document.getElementById("reviewed-count"),
  totalCount: document.getElementById("total-count"),
  remainingLabel: document.getElementById("remaining-label"),
  sideProgressFill: document.getElementById("side-progress-fill"),
  countConfirm: document.getElementById("count-confirm"),
  countReject: document.getElementById("count-reject"),
  recentList: document.getElementById("recent-list"),
  recentCount: document.getElementById("recent-count"),
  exportButton: document.getElementById("export-button"),
  exportNote: document.getElementById("export-note"),
  candidateSource: document.getElementById("candidate-source"),
  dialog: document.getElementById("confirm-dialog"),
  dialogTitle: document.getElementById("dialog-title"),
  dialogMessage: document.getElementById("dialog-message"),
  dialogPreview: document.getElementById("dialog-preview"),
  dialogConfirm: document.getElementById("dialog-confirm"),
  dialogCancel: document.getElementById("dialog-cancel"),
  dialogClose: document.getElementById("dialog-close"),
  toast: document.getElementById("toast"),
};

let toastTimer = null;

async function api(path, options = {}) {
  const request = {
    headers: { "Content-Type": "application/json" },
    ...options,
  };
  const response = await fetch(path, request);
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new Error(payload?.error || `请求失败 (${response.status})`);
  }
  return payload?.result;
}

function currentItem() {
  if (!state.session || !state.currentId) return null;
  return state.session.items.find((item) => item.id === state.currentId) || null;
}

function queueItems() {
  if (!state.session) return [];
  if (state.filter === "all") return state.session.items;
  return state.session.items.filter((item) => !item.verdict);
}

function syncCurrentToQueue() {
  const queue = queueItems();
  if (!queue.length) {
    state.currentId = null;
    state.loadedId = null;
    return;
  }
  if (!queue.some((item) => item.id === state.currentId)) {
    state.currentId = queue[0].id;
  }
}

function metrics() {
  const items = state.session?.items || [];
  const counts = Object.fromEntries(Object.keys(VERDICTS).map((key) => [key, 0]));
  for (const item of items) {
    if (item.verdict && counts[item.verdict] !== undefined) counts[item.verdict] += 1;
  }
  const reviewed = Object.values(counts).reduce((total, value) => total + value, 0);
  const exportable = counts.confirm + counts.reject;
  return { counts, reviewed, exportable, total: items.length, remaining: items.length - reviewed };
}

function render() {
  if (!state.session) return;
  syncCurrentToQueue();
  renderStats();
  renderRecent();
  renderQueuePosition();
  renderItem();
}

function renderStats() {
  const { counts, reviewed, exportable, total, remaining } = metrics();
  const percentage = total ? (reviewed / total) * 100 : 0;

  elements.reviewerChip.textContent = `复核员 ${state.session.reviewer}`;
  elements.topProgress.textContent = `${reviewed} / ${total}`;
  elements.progressFill.style.width = `${percentage}%`;
  elements.reviewedCount.textContent = String(reviewed);
  elements.totalCount.textContent = `/ ${total}`;
  elements.remainingLabel.textContent = `剩余 ${remaining} 条`;
  elements.sideProgressFill.style.width = `${percentage}%`;
  elements.countConfirm.textContent = String(counts.confirm);
  elements.countReject.textContent = String(counts.reject);
  elements.exportButton.disabled = state.busy;
  elements.exportNote.textContent = state.exportMessage || (
    exportable
      ? `${exportable} 条可进入构建数据`
      : "等待复核结果"
  );
  elements.candidateSource.textContent = state.session.candidates_path;
}

function renderQueuePosition() {
  const queue = queueItems();
  const index = queue.findIndex((item) => item.id === state.currentId);
  if (!queue.length) {
    elements.queuePosition.textContent = "当前队列已清空";
  } else {
    elements.queuePosition.textContent = `第 ${index + 1} / ${queue.length} 条`;
  }
  elements.prevButton.disabled = state.busy || !queue.length || index <= 0;
  elements.nextButton.disabled =
    state.busy || !queue.length || index < 0 || index >= queue.length - 1;
}

function setLink(element, href, label) {
  const safe = /^https?:\/\//.test(href || "") ? href : "";
  element.href = safe || "#";
  element.textContent = label || "--";
  element.classList.toggle("is-disabled", !safe);
  if (safe) {
    element.setAttribute("target", "_blank");
    element.setAttribute("rel", "noreferrer");
  }
}

function shortCommit(commit) {
  return commit ? commit.slice(0, 12) : "--";
}

function repoName(repoUrl) {
  const match = String(repoUrl || "").match(/^https?:\/\/github\.com\/([^/]+\/[^/#?]+)/);
  return match ? match[1].replace(/\.git$/, "") : (repoUrl || "--");
}

function encodeFilePath(filePath) {
  return String(filePath || "").split("/").map(encodeURIComponent).join("/");
}

function deriveFileUrl(item, commit, suppliedUrl) {
  if (suppliedUrl) return suppliedUrl;
  if (!item.repo_url || !commit || !item.file_path) return "";
  return `${item.repo_url.replace(/\/$/, "")}/blob/${commit}/${encodeFilePath(item.file_path)}`;
}

function renderItem() {
  const item = currentItem();
  const queue = queueItems();
  const isEmpty = !item;
  elements.reviewPanel.classList.toggle("is-empty", isEmpty);
  elements.reviewPanel.dataset.emptyMessage =
    state.filter === "unlabeled" && metrics().remaining === 0
      ? "全部候选已完成复核。"
      : "当前筛选条件下没有候选。";

  elements.verdictButtons.forEach((button) => {
    const active = item?.verdict === button.dataset.verdict;
    button.classList.toggle("is-selected", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
    button.disabled = isEmpty || state.busy;
  });

  if (isEmpty) {
    renderModelAudit(null);
    elements.itemStatus.textContent = queue.length ? "未复核" : "队列已清空";
    elements.statusDot.classList.remove("is-reviewed");
    elements.clearButton.hidden = true;
    elements.prevButton.disabled = true;
    elements.nextButton.disabled = true;
    return;
  }

  const verdictName = item.verdict ? VERDICTS[item.verdict].name : "未复核";
  elements.itemStatus.textContent = verdictName;
  elements.statusDot.classList.toggle("is-reviewed", Boolean(item.verdict));
  elements.clearButton.hidden = !item.verdict;
  elements.clearButton.disabled = state.busy;

  if (state.loadedId !== item.id) {
    populateForm(item);
    state.loadedId = item.id;
  }
  renderModelAudit(item);
  renderVerdictBadge(item);
  setFormDisabled(state.busy);
}

function renderVerdictBadge(item) {
  elements.verdictBadge.className = "verdict-badge";
  elements.verdictBadge.textContent = item.verdict ? VERDICTS[item.verdict].name : "未复核";
  if (item.verdict) elements.verdictBadge.classList.add(item.verdict);
}

function buildRuleOptions() {
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "选择规则";
  elements.ruleSelect.replaceChildren(blank);
  for (const rule of state.session.rules) {
    const option = document.createElement("option");
    option.value = rule.id;
    option.textContent = `${rule.id} · ${rule.title}`;
    option.dataset.acceptedCwes = (rule.accepted_cwes || [rule.cwe]).filter(Boolean).join(",");
    elements.ruleSelect.append(option);
  }
}

function syncRuleAvailability(cwe) {
  for (const option of elements.ruleSelect.options) {
    if (!option.value) continue;
    const accepted = option.dataset.acceptedCwes.split(",").filter(Boolean);
    option.disabled = Boolean(cwe && accepted.length && !accepted.includes(cwe));
    if (option.disabled && option.selected) elements.ruleSelect.value = "";
  }
}

function ruleById(ruleId) {
  return state.session.rules.find((rule) => rule.id === ruleId) || null;
}

function compatibleModelRule(item) {
  const rule = ruleById(item.model_rule_id);
  if (!rule) return "";
  const accepted = (rule.accepted_cwes || [rule.cwe]).filter(Boolean);
  if (item.cwe && accepted.length && !accepted.includes(item.cwe)) return "";
  return rule.id;
}

function renderModelAudit(item) {
  const decisionLabels = {
    confirmed: "AI 倾向确认",
    rejected: "AI 倾向误判",
  };
  const hasAudit = Boolean(item?.model_decision);
  elements.modelAuditStrip.hidden = !hasAudit;
  if (!hasAudit) return;

  const confidence = Number(item.model_confidence);
  elements.modelAuditDecision.textContent =
    decisionLabels[item.model_decision] || item.model_decision;
  elements.modelAuditConfidence.textContent = Number.isFinite(confidence)
    ? `置信度 ${Math.round(confidence * 100)}%`
    : "置信度未知";
  elements.modelAuditExplanation.textContent =
    item.model_explanation || "模型未提供判定解释。";
  const details = [];
  if (item.model_cwe || item.model_rule_id) {
    details.push([item.model_cwe || "CWE 未知", item.model_rule_id || "规则未定"].join(" · "));
  }
  if (item.model_evidence_notes) details.push(item.model_evidence_notes);
  if (item.model_error) details.push(`调用/解析问题：${item.model_error}`);
  const reasons = item.review_selection?.reasons || [];
  if (reasons.length) details.push(`进入人工队列：${reasons.join(", ")}`);
  elements.modelAuditDetail.textContent = details.join("\n");
  elements.modelAuditDetail.hidden = !details.length;
}

function populateForm(item) {
  elements.packageName.textContent = item.package || "未知包";
  elements.itemCwe.textContent = item.cwe || "CWE 未知";
  elements.itemAdvisory.textContent = item.advisory_id || "advisory 未知";
  elements.itemCve.textContent = item.cve_id || "无 CVE";
  elements.filePath.textContent = item.file_path || "--";
  elements.filePath.title = item.file_path || "";

  setLink(elements.repoLink, item.repo_url, repoName(item.repo_url));
  const fixUrl = item.repo_url && item.fix_commit
    ? `${item.repo_url.replace(/\/$/, "")}/commit/${item.fix_commit}`
    : "";
  setLink(elements.fixCommitLink, fixUrl, shortCommit(item.fix_commit));
  setLink(elements.notificationLink, item.notification_url, "查看公告");
  setLink(
    elements.vulnCodeLink,
    deriveFileUrl(item, item.vuln_commit, item.code_vuln_url),
    "来源"
  );
  setLink(
    elements.fixedCodeLink,
    deriveFileUrl(item, item.fix_commit, item.code_fixed_url),
    "来源"
  );

  elements.codeVuln.value = item.code_vuln || "";
  elements.codeFixed.value = item.code_fixed || "";
  elements.codeVuln.placeholder = "没有自动提取到漏洞前代码";
  elements.codeFixed.placeholder = "没有自动提取到修复后代码";

  syncRuleAvailability(item.cwe);
  const selectedRule = item.rule_id || compatibleModelRule(item) || item.rule_hint || "";
  elements.ruleSelect.value = selectedRule;
  const selectedMeta = ruleById(selectedRule);
  elements.severitySelect.value =
    item.severity || item.model_severity || selectedMeta?.severity || "HIGH";
  elements.splitSelect.value = item.split || "train";
  elements.explanationInput.value = item.explanation || item.model_explanation || "";
  elements.findingInput.value = item.finding || item.model_finding || "";
  elements.noteInput.value = item.note || "";
}

function setFormDisabled(disabled) {
  [
    elements.codeVuln,
    elements.codeFixed,
    elements.ruleSelect,
    elements.severitySelect,
    elements.splitSelect,
    elements.explanationInput,
    elements.findingInput,
    elements.noteInput,
  ].forEach((control) => {
    control.disabled = disabled;
  });
}

function renderRecent() {
  const items = state.session?.items || [];
  const byId = new Map(items.map((item) => [item.id, item]));
  state.recentIds = state.recentIds.filter((id) => byId.get(id)?.verdict);
  const recent = state.recentIds
    .map((id) => byId.get(id))
    .filter(Boolean)
    .slice(0, 5);

  elements.recentCount.textContent = String(recent.length);
  elements.recentList.replaceChildren();
  if (!recent.length) {
    const empty = document.createElement("li");
    empty.className = "recent-empty";
    empty.textContent = "尚无历史记录";
    elements.recentList.append(empty);
    return;
  }

  for (const item of recent) {
    const row = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.recentId = item.id;

    const id = document.createElement("span");
    id.className = "recent-id";
    id.textContent = item.package || item.id;
    id.title = item.id;
    const label = document.createElement("span");
    label.className = `recent-label ${item.verdict}`;
    label.textContent = VERDICTS[item.verdict].name;
    button.append(id, label);
    button.addEventListener("click", () => {
      state.filter = "all";
      state.currentId = item.id;
      state.loadedId = null;
      updateFilterButtons();
      render();
    });
    row.append(button);
    elements.recentList.append(row);
  }
}

function updateFilterButtons() {
  elements.filterButtons.forEach((button) => {
    const active = button.dataset.filter === state.filter;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function move(direction) {
  const queue = queueItems();
  if (!queue.length) return;
  let index = queue.findIndex((item) => item.id === state.currentId);
  if (index < 0) index = 0;
  const nextIndex = Math.max(0, Math.min(queue.length - 1, index + direction));
  state.currentId = queue[nextIndex].id;
  state.loadedId = null;
  render();
}

function nextUnreviewedAfterCurrent() {
  const items = state.session.items;
  const currentIndex = items.findIndex((item) => item.id === state.currentId);
  const ordered = items.slice(currentIndex + 1).concat(items.slice(0, currentIndex + 1));
  return ordered.find((item) => !item.verdict) || null;
}

function collectForm() {
  return {
    code_vuln: elements.codeVuln.value,
    code_fixed: elements.codeFixed.value,
    rule_id: elements.ruleSelect.value,
    severity: elements.severitySelect.value,
    split: elements.splitSelect.value,
    explanation: elements.explanationInput.value,
    finding: elements.findingInput.value,
    note: elements.noteInput.value,
  };
}

function preflight(verdict) {
  const data = collectForm();
  if (verdict === "confirm") {
    if (!data.code_vuln.trim() || !data.code_fixed.trim()) {
      return "确认漏洞需要漏洞前和修复后两段代码";
    }
    if (!data.rule_id) return "确认漏洞需要选择规则";
    if (!data.explanation.trim()) return "确认漏洞需要填写判定解释";
  }
  if (verdict === "reject") {
    if (!data.code_vuln.trim()) return "判定误报需要漏洞前代码作为 finding 上下文";
    if (!data.explanation.trim()) return "判定误报需要填写判定解释";
  }
  return "";
}

function requestVerdict(verdict) {
  const item = currentItem();
  if (!item || state.busy) return;
  const error = preflight(verdict);
  if (error) {
    showToast(error, true);
    return;
  }

  state.pendingAction = { type: "review", verdict };
  const previous = item.verdict ? `当前为“${VERDICTS[item.verdict].name}”，` : "";
  elements.dialogTitle.textContent = "确认复核结论";
  elements.dialogMessage.textContent =
    `${previous}确认将 ${item.package || item.id} / ${item.cve_id || item.advisory_id} ` +
    `标记为“${VERDICTS[verdict].name}”。`;
  elements.dialogPreview.textContent = [
    `${item.cwe || "CWE 未知"} · ${collectForm().rule_id || "未选规则"}`,
    item.file_path || "文件路径未提取",
    elements.explanationInput.value.trim() || "判定解释为空",
  ].join("\n");
  elements.dialogConfirm.textContent = "确认";
  elements.dialog.showModal();
}

function requestClear() {
  const item = currentItem();
  if (!item?.verdict || state.busy) return;
  state.pendingAction = { type: "clear", verdict: item.verdict };
  elements.dialogTitle.textContent = "清除复核结论";
  elements.dialogMessage.textContent =
    `移除本条候选当前的“${VERDICTS[item.verdict].name}”结论。`;
  elements.dialogPreview.textContent =
    `${item.package || item.id}\n${item.cve_id || item.advisory_id || item.id}`;
  elements.dialogConfirm.textContent = "清除";
  elements.dialog.showModal();
}

async function confirmPendingAction() {
  const action = state.pendingAction;
  const item = currentItem();
  if (!action || !item || state.busy) return;

  state.busy = true;
  elements.dialogConfirm.disabled = true;
  elements.verdictButtons.forEach((button) => {
    button.disabled = true;
  });
  setFormDisabled(true);
  try {
    if (action.type === "review") {
      const updated = await api("/api/review", {
        method: "POST",
        body: JSON.stringify({ id: item.id, verdict: action.verdict, ...collectForm() }),
      });
      replaceItem(updated);
      state.exportMessage = "";
      state.recentIds = [
        updated.id,
        ...state.recentIds.filter((id) => id !== updated.id),
      ];
      state.loadedId = null;
      if (state.filter === "unlabeled") {
        const next = nextUnreviewedAfterCurrent();
        state.currentId = next?.id || null;
      }
      showToast(`已记录为“${VERDICTS[action.verdict].name}”`);
    } else {
      const updated = await api(`/api/review/${encodeURIComponent(item.id)}`, {
        method: "DELETE",
      });
      replaceItem(updated);
      state.exportMessage = "";
      state.recentIds = state.recentIds.filter((id) => id !== updated.id);
      state.loadedId = null;
      showToast("已清除本条结论");
    }
    elements.dialog.close();
  } catch (error) {
    showToast(error.message, true);
  } finally {
    state.busy = false;
    state.pendingAction = null;
    elements.dialogConfirm.disabled = false;
    render();
  }
}

function replaceItem(updated) {
  const index = state.session.items.findIndex((item) => item.id === updated.id);
  if (index >= 0) state.session.items[index] = updated;
}

async function exportData() {
  if (state.busy) return;
  state.busy = true;
  renderStats();
  elements.exportButton.disabled = true;
  try {
    const result = await api("/api/export", { method: "POST" });
    state.exportMessage = `detect ${result.detect} / triage ${result.triage}`;
    showToast(`已重建 ${result.detect_path} 和 ${result.triage_path}`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    state.busy = false;
    render();
  }
}

function showToast(message, isError = false) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("is-error", isError);
  elements.toast.classList.add("is-visible");
  toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 2600);
}

function bindCodeEditorTab(textarea) {
  textarea.addEventListener("keydown", (event) => {
    if (event.key !== "Tab" || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault();
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    textarea.setRangeText("    ", start, end, "end");
  });
}

function bindEvents() {
  elements.verdictButtons.forEach((button) => {
    button.addEventListener("click", () => requestVerdict(button.dataset.verdict));
  });

  elements.filterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      state.loadedId = null;
      updateFilterButtons();
      render();
    });
  });

  elements.ruleSelect.addEventListener("change", () => {
    const rule = ruleById(elements.ruleSelect.value);
    if (rule) elements.severitySelect.value = rule.severity || "HIGH";
  });

  elements.prevButton.addEventListener("click", () => move(-1));
  elements.nextButton.addEventListener("click", () => move(1));
  elements.clearButton.addEventListener("click", requestClear);
  elements.exportButton.addEventListener("click", exportData);
  elements.dialogCancel.addEventListener("click", () => elements.dialog.close());
  elements.dialogClose.addEventListener("click", () => elements.dialog.close());
  elements.dialogConfirm.addEventListener("click", confirmPendingAction);
  bindCodeEditorTab(elements.codeVuln);
  bindCodeEditorTab(elements.codeFixed);

  elements.dialog.addEventListener("cancel", () => {
    state.pendingAction = null;
  });
  elements.dialog.addEventListener("click", (event) => {
    if (event.target === elements.dialog) elements.dialog.close();
  });
  elements.dialog.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && state.pendingAction && !state.busy) {
      event.preventDefault();
      confirmPendingAction();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (elements.dialog.open || state.busy) return;
    const target = event.target;
    const editing = target instanceof HTMLInputElement
      || target instanceof HTMLTextAreaElement
      || target instanceof HTMLSelectElement
      || target?.isContentEditable;
    if (editing) return;
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "1") requestVerdict("confirm");
    if (event.key === "2") requestVerdict("reject");
    if (event.key === "ArrowLeft") move(-1);
    if (event.key === "ArrowRight") move(1);
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.busy) return;
    event.preventDefault();
  });
}

async function init() {
  bindEvents();
  try {
    state.session = await api("/api/session");
    buildRuleOptions();
    const reviewedItems = state.session.items
      .filter((item) => item.verdict)
      .sort((a, b) => String(b.reviewed_at || "").localeCompare(String(a.reviewed_at || "")));
    state.recentIds = reviewedItems.slice(0, 5).map((item) => item.id);
    state.currentId = state.session.items.find((item) => !item.verdict)?.id
      || state.session.items[0]?.id
      || null;
    updateFilterButtons();
    render();
  } catch (error) {
    elements.reviewPanel.classList.add("is-empty");
    elements.reviewPanel.dataset.emptyMessage = `加载失败：${error.message}`;
    showToast(error.message, true);
  }
}

init();
