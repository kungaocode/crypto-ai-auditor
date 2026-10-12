// Shared rendering and DOM helpers.

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export const SEVERITY_LABEL = {
  CRITICAL: "严重",
  HIGH: "高危",
  MEDIUM: "中危",
  LOW: "低危",
  INFO: "提示",
};

export const VERDICT_LABEL = {
  CONFIRMED: "已确认",
  UNCERTAIN: "待复核",
  REJECTED: "已排除",
};

export const RISK_LABEL = {
  CRITICAL: "严重",
  HIGH: "高风险",
  MEDIUM: "中风险",
  LOW: "低风险",
  INFO: "未发现风险",
};

export const SEVERITY_COLOR = {
  CRITICAL: "#ff4d6d",
  HIGH: "#ff8a3d",
  MEDIUM: "#f5c451",
  LOW: "#4ea1ff",
  INFO: "#8b98a9",
};

export function severityBadge(severity) {
  const key = String(severity || "INFO").toUpperCase();
  return `<span class="badge sev-${escapeHtml(key)}">${escapeHtml(SEVERITY_LABEL[key] || key)}</span>`;
}

export function verdictBadge(verdict) {
  const key = String(verdict || "UNCERTAIN").toUpperCase();
  return `<span class="badge verdict-${escapeHtml(key)}">${escapeHtml(VERDICT_LABEL[key] || key)}</span>`;
}

export function ruleTag(ruleId) {
  return `<span class="rule-tag">${escapeHtml(ruleId)}</span>`;
}

export function cweTag(cwe) {
  if (!cwe) return "";
  return `<span class="cwe-tag">${escapeHtml(cwe)}</span>`;
}

export function formatDate(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatConfidence(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${Math.round(number * 100)}%`;
}

export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url || "—";
  }
}

export function codeBlock(source, startLine = 1, highlightLine = null) {
  const lines = String(source ?? "").split("\n");
  const html = lines
    .map((text, index) => {
      const number = startLine + index;
      const hit = highlightLine != null && number === highlightLine ? " is-hit" : "";
      return `<div class="code-line${hit}"><span class="ln">${number}</span><span class="lt">${escapeHtml(text) || " "}</span></div>`;
    })
    .join("");
  return `<div class="context-code"><code>${html}</code></div>`;
}

export function diffBlock(diffLines) {
  if (!diffLines || !diffLines.length) {
    return `<div class="empty-mini">该文件没有可应用的自动修复。</div>`;
  }
  let oldLine = 0;
  let newLine = 0;
  const html = diffLines
    .map((line) => {
      let cls = "ctx";
      let label = "";
      if (line.startsWith("@@")) {
        cls = "hunk";
        const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        if (match) {
          oldLine = Number(match[1]);
          newLine = Number(match[2]);
        }
        label = line;
      } else if (line.startsWith("+++") || line.startsWith("---")) {
        cls = "header";
        label = line;
      } else if (line.startsWith("+")) {
        cls = "add";
        label = `${newLine}`;
        newLine += 1;
      } else if (line.startsWith("-")) {
        cls = "del";
        label = `${oldLine}`;
        oldLine += 1;
      } else {
        label = `${newLine || oldLine}`;
        oldLine += 1;
        newLine += 1;
      }
      const body = cls === "add" || cls === "del" || cls === "ctx" ? line.slice(1) : line;
      return `<div class="diff-line ${cls}"><span class="dl">${escapeHtml(label)}</span><span class="dt">${escapeHtml(body) || " "}</span></div>`;
    })
    .join("");
  return `<div class="code-pane diff-pane" id="diff-pane"><code>${html}</code></div>`;
}

export function gauge(score, level) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, Number(score) || 0));
  const offset = circumference * (1 - clamped / 100);
  const color = SEVERITY_COLOR[level] || "#2dd4bf";
  return `
    <div class="gauge">
      <svg viewBox="0 0 100 100">
        <circle class="gauge-track" cx="50" cy="50" r="${radius}"></circle>
        <circle class="gauge-fill" cx="50" cy="50" r="${radius}"
          stroke="${color}"
          stroke-dasharray="${circumference.toFixed(1)}"
          stroke-dashoffset="${offset.toFixed(1)}"></circle>
      </svg>
      <div class="gauge-center">
        <strong style="color:${color}">${clamped}</strong>
        <span>/ 100</span>
      </div>
    </div>`;
}

export function barRow(label, value, max, color) {
  const total = Math.max(1, Number(max) || 1);
  const width = Math.max(2, Math.round((Number(value) / total) * 100));
  return `
    <div class="bar-row">
      <span class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${width}%;background:${color}"></span></span>
      <span class="bar-value">${escapeHtml(value)}</span>
    </div>`;
}

export function toast(message, kind = "info") {
  const stack = document.getElementById("toast-stack");
  if (!stack) return;
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  const glyph = kind === "ok" ? "check" : kind === "err" ? "alert" : "info";
  node.innerHTML = `<span data-icon="${glyph}"></span><span>${escapeHtml(message)}</span>`;
  stack.appendChild(node);
  import("./icons.js").then(({ hydrateIcons }) => hydrateIcons(node));
  const timer = window.setTimeout(() => node.remove(), 4200);
  node.dataset.timer = String(timer);
}

export async function copyText(text, successMessage = "已复制到剪贴板") {
  try {
    await navigator.clipboard.writeText(text);
    toast(successMessage, "ok");
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    toast(successMessage, "ok");
  }
}

export function downloadText(filename, text, mime = "text/plain") {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function topEntries(map, limit = 6) {
  return Object.entries(map || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
}
