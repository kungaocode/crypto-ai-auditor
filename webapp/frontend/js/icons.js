// Minimal inline stroke-icon set (lucide-style, no external dependency).

const PATHS = {
  shield: '<path d="M12 3l7 3v5.5c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6l7-3z"/><path d="M9.2 12.2l2 2 3.6-3.9"/>',
  terminal: '<path d="M5 7l4 4-4 4"/><path d="M12 15h7"/>',
  chart: '<path d="M4 20V6"/><path d="M4 20h16"/><rect x="7" y="12" width="3" height="5"/><rect x="12" y="8" width="3" height="9"/><rect x="17" y="10" width="3" height="7"/>',
  book: '<path d="M5 4h11a2 2 0 0 1 2 2v14H7a2 2 0 0 1-2-2V4z"/><path d="M5 4v14"/><path d="M9 8h5"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><path d="M12 8v4l3 2"/>',
  sparkles: '<path d="M12 4l1.6 4.4L18 10l-4.4 1.6L12 16l-1.6-4.4L6 10l4.4-1.6L12 4z"/><path d="M18 15l.8 2.2L21 18l-2.2.8L18 21l-.8-2.2L15 18l2.2-.8L18 15z"/>',
  upload: '<path d="M12 16V5"/><path d="M7 10l5-5 5 5"/><path d="M5 19h14"/>',
  play: '<path d="M7 5l12 7-12 7V5z"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-.6 4"/><path d="M20 5v6h-6"/>',
  search: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4-4"/>',
  close: '<path d="M6 6l12 12"/><path d="M18 6L6 18"/>',
  alert: '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
  check: '<path d="M5 12l4.5 4.5L19 7"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
  file: '<path d="M6 3h8l4 4v14H6V3z"/><path d="M14 3v4h4"/>',
  download: '<path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
  arrowRight: '<path d="M5 12h14"/><path d="M13 6l6 6-6 6"/>',
  code: '<path d="M8 8l-4 4 4 4"/><path d="M16 8l4 4-4 4"/><path d="M13 5l-2 14"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="1"/><path d="M10 3v3M14 3v3M10 18v3M14 18v3M3 10h3M3 14h3M18 10h3M18 14h3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  chevron: '<path d="M9 6l6 6-6 6"/>',
  filter: '<path d="M4 5h16l-6 7v6l-4-2v-4L4 5z"/>',
  wrench: '<path d="M15 4a5 5 0 0 0-4.6 7L4 17.4 6.6 20l6.4-6.4A5 5 0 1 0 15 4z"/><path d="M15 9h.01"/>',
  layers: '<path d="M12 4l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 11l8-8"/><path d="M16 4l3 3"/><path d="M14 6l3 3"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
};

export function icon(name, className = "") {
  const inner = PATHS[name] || PATHS.info;
  const cls = className ? ` class="${className}"` : "";
  return `<svg${cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
}

export function hydrateIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((node) => {
    if (node.dataset.hydrated === "1") return;
    node.innerHTML = icon(node.dataset.icon);
    node.dataset.hydrated = "1";
  });
}
