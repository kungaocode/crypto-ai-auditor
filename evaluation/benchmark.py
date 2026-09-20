"""Benchmark: dual-slice evaluation over labeled v2 records (roadmap §7).

Slices
  detect : records with task=detect -> predict {vulnerable, cwe}; GT label.
           Metric: Detection Recall/Precision/F1/Acc + CWE Acc (on positives).
  domain : records with task=triage (code + Semgrep candidate) -> verdict
           Confirm/Reject; GT label.verdict.
           Metric: Confirm Recall (GT-TP kept) / FPR (GT-FP rejected) / Acc.

Systems (predictor per slice)
  static : semgrep rules over the code (detect) / accept-all (domain, system ①)
  llm    : model backend raw (kind from config: mock | cloud)
  agent  : SecurityAgent (backend + fixture guard) on triage

Config (configs/benchmark.yaml):
  model: {kind, model_id, api_key?, base_url?}
  splits: {detect: path, domain: path}
  static: {rules: path}

Usage:
  python main.py --benchmark --config configs/benchmark.yaml
"""
import json
import statistics
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import yaml

from agent.agent import SecurityAgent
from model import inference as model_inf


# ------------------------------------------------------------- loading / static


def load_records(path: Path) -> List[dict]:
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def _rule_cwe_map(rules_dir: Path) -> dict:
    m = {}
    for y in sorted(Path(rules_dir).glob("crypto-*/rule.yaml")):
        for r in yaml.safe_load(y.read_text(encoding="utf-8")).get("rules", []):
            m[r["id"]] = (r.get("metadata", {}).get("cwe", ""),
                          r.get("severity", r.get("metadata", {}).get("severity", "WARNING")))
    return m


def static_detect(records: List[dict], rules_dir: Path) -> List[dict]:
    """Batch semgrep over snippets -> per-record {vulnerable, cwe, severity}."""
    rmap = _rule_cwe_map(rules_dir)
    codes = [r.get("code", "") for r in records]
    hits: dict = {}
    if codes and any(codes):
        with tempfile.TemporaryDirectory(prefix="bm_static_") as td:
            for i, c in enumerate(codes):
                Path(td, f"f{i:06d}.py").write_text(c, encoding="utf-8")
            proc = subprocess.run(["semgrep", "--config", str(rules_dir), "--json",
                                   "--quiet", td], capture_output=True, text=True)
            try:
                results = json.loads(proc.stdout or "{}").get("results", [])
            except json.JSONDecodeError:
                results = []
            for h in results:
                idx = int(Path(h["path"]).name[1:6])
                cwe, sev = rmap.get(h["check_id"].split(".")[-1], ("", "WARNING"))
                hits.setdefault(idx, {"cwe": cwe, "severity": sev})
    preds = []
    for i in range(len(records)):
        h = hits.get(i)
        preds.append({"vulnerable": bool(h),
                      "cwe": h["cwe"] if h else "",
                      "severity": h["severity"] if h else ""})
    return preds


# ------------------------------------------------------------- metrics


def _detect_metrics(records: List[dict], preds: List[dict]) -> dict:
    tp = fp = fn = tn = 0
    cwe_hit, cwe_total = 0, 0
    for rec, p in zip(records, preds):
        gt = bool(rec["label"].get("vulnerable"))
        pv = bool(p.get("vulnerable"))
        if gt and pv:
            tp += 1
            if rec["label"].get("cwe"):
                cwe_total += 1
                cwe_hit += int(str(p.get("cwe", "")).startswith(str(rec["label"]["cwe"])))
        elif gt and not pv:
            fn += 1
        elif not gt and pv:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * recall * precision / (recall + precision) if (recall + precision) else 0.0
    return {
        "n": len(records), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 4), "precision": round(precision, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(records), 4) if records else 0.0,
        "cwe_acc": round(cwe_hit / cwe_total, 4) if cwe_total else None,
    }


def _triage_metrics(records: List[dict], preds: List[dict]) -> dict:
    keep_tp = drop_tp = keep_fp = drop_fp = 0
    gt_confirm = gt_reject = 0
    for rec, p in zip(records, preds):
        gt = rec["label"].get("verdict")
        pv = str(p.get("verdict", "")).lower()
        p_conf = pv == "confirm"
        if gt == "Confirm":
            gt_confirm += 1
            keep_tp += 1 if p_conf else 0
            drop_tp += 0 if p_conf else 1
        else:
            gt_reject += 1
            keep_fp += 1 if p_conf else 0
            drop_fp += 0 if p_conf else 1
    recall = keep_tp / gt_confirm if gt_confirm else 0.0
    fpr = keep_fp / gt_reject if gt_reject else 0.0
    return {
        "n": len(records), "gt_confirm": gt_confirm, "gt_reject": gt_reject,
        "confirm_recall": round(recall, 4), "fpr": round(fpr, 4),
        "accuracy": round((keep_tp + drop_fp) / len(records), 4) if records else 0.0,
    }


# ------------------------------------------------------------- systems


def run_detect(records: List[dict], cfg: dict, systems: List[str],
               backend, rules_dir: Path) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for sys_name in systems:
        if sys_name == "static":
            preds = static_detect(records, rules_dir)
        elif sys_name in {"llm", "agent"}:
            preds = []
            for rec in records:
                preds.append(backend.detect(rec.get("code", "")))
        else:
            raise ValueError(f"unknown detect system {sys_name!r}")
        results[sys_name] = {"metrics": _detect_metrics(records, preds), "preds": preds}
    return results


def run_triage(records: List[dict], cfg: dict, systems: List[str],
               backend, agent) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for sys_name in systems:
        preds = []
        for rec in records:
            code, finding = rec.get("code", ""), rec.get("finding", "")
            if sys_name == "static":                      # accept-all (system ①)
                preds.append({"verdict": "Confirm"})
            elif sys_name == "llm":
                preds.append(backend.triage(code, finding))
            elif sys_name == "agent":
                out = agent.triage_one(code, finding)
                preds.append({"verdict": _triage_verdict(out)})
            else:
                raise ValueError(f"unknown triage system {sys_name!r}")
        results[sys_name] = {"metrics": _triage_metrics(records, preds), "preds": preds}
    return results


def _triage_verdict(agent_out: dict) -> str:
    return "Confirm" if agent_out["verdict"] == "CONFIRMED" else "Reject"


# ------------------------------------------------------------- entry


def run_benchmark(config_path: Path, out_dir: Path | None = None) -> Dict[str, Any]:
    cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    splits = cfg.get("splits", {})
    rules_dir = Path(cfg.get("static", {}).get("rules", "rules"))
    backend = model_inf.get_backend(config=cfg)
    agent = SecurityAgent(backend=backend)

    summary: Dict[str, Any] = {"config": str(config_path), "model_kind": type(backend).__name__}
    detect_recs = load_records(Path(splits["detect"])) if splits.get("detect") else []
    domain_recs = load_records(Path(splits["domain"])) if splits.get("domain") else []

    if detect_recs:
        systems = [s for s in ("static", "llm") if s in cfg.get("systems", ["static", "llm"])]
        summary["detect"] = run_detect(detect_recs, cfg, systems, backend, rules_dir)
    if domain_recs:
        systems = [s for s in ("static", "llm", "agent")
                   if s in cfg.get("systems", ["static", "llm", "agent"])]
        summary["domain"] = run_triage(domain_recs, cfg, systems, backend, agent)

    _print_summary(summary)

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "benchmark.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        _write_markdown(summary, out_dir / "benchmark.md")
        print(f"[+] Benchmark report -> {out_dir / 'benchmark.json'}")
    return summary


def _print_summary(summary: dict) -> None:
    print("\n==== BENCHMARK (mock self-test / model) ====")
    if "detect" in summary:
        print("\n[detect slice]  metrics per system")
        for name, res in summary["detect"].items():
            m = res["metrics"]
            print(f"  {name:<7} recall={m['recall']:.3f} precision={m['precision']:.3f} "
                  f"f1={m['f1']:.3f} acc={m['accuracy']:.3f} cwe_acc={m['cwe_acc']}")
    if "domain" in summary:
        print("\n[domain slice]  triage metrics per system")
        for name, res in summary["domain"].items():
            m = res["metrics"]
            print(f"  {name:<7} confirm_recall={m['confirm_recall']:.3f} "
                  f"fpr={m['fpr']:.3f} acc={m['accuracy']:.3f} (n={m['n']})")
    print()


def _write_markdown(summary: dict, path: Path) -> None:
    lines = ["# Benchmark Report\n"]
    if "detect" in summary:
        lines.append("## Detect slice\n\n| system | recall | precision | f1 | accuracy | cwe_acc |")
        lines.append("|---|---|---|---|---|---|")
        for name, res in summary["detect"].items():
            m = res["metrics"]
            lines.append(f"| {name} | {m['recall']:.3f} | {m['precision']:.3f} | {m['f1']:.3f} "
                         f"| {m['accuracy']:.3f} | {m['cwe_acc']} |")
        lines.append("")
    if "domain" in summary:
        lines.append("## Domain slice (triage)\n\n| system | confirm_recall | fpr | accuracy | n |")
        lines.append("|---|---|---|---|---|")
        for name, res in summary["domain"].items():
            m = res["metrics"]
            lines.append(f"| {name} | {m['confirm_recall']:.3f} | {m['fpr']:.3f} "
                         f"| {m['accuracy']:.3f} | {m['n']} |")
        lines.append("")
    path.write_text("\n".join(lines))
