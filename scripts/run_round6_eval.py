#!/usr/bin/env python3
"""Round-6 final evaluation against the deployed fine-tuned model.

Two suites, both against the deployed endpoint (env-driven, see below):

  1. FINAL TEST SET  — the de-leaked frozen validation slices
       data/round6/validation_frozen/detect_eval.jsonl   (n=19, pos=7/neg=12)
       data/round6/validation_frozen/triage_eval.jsonl   (n=36, Confirm=4/Reject=32)
  2. MODEL CAPABILITY — the 18 grounded triage probes
       data/round2/eval/triage_probes.json               (n=18, Confirm=12/Reject=6)

Writes JSON + a single Markdown report under data/round6/eval/.

Usage (from repo root):
  export LLM_API_KEY="$(sed -n '2p' api.txt)"          # Bailian workspace key
  export LLM_MODEL_ID="qwen3-4b-instruct-2507-5f8261ad123d"
  export LLM_WORKSPACE="ws-avxkjb2tq5lq1gwm"
  python3 scripts/run_round6_eval.py
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from model.inference import CloudBackend, LLMError
from evaluation.benchmark import _detect_metrics, _triage_metrics, static_detect

ROUND6 = ROOT / "data" / "round6"
DETECT_PATH = ROUND6 / "validation_frozen" / "detect_eval.jsonl"
TRIAGE_PATH = ROUND6 / "validation_frozen" / "triage_eval.jsonl"
PROBES_PATH = ROOT / "data" / "round2" / "eval" / "triage_probes.json"
RULES_DIR = ROOT / "rules"
OUT_DIR = ROUND6 / "eval"

# Deployed endpoint discovered via the Bailian fine-tune/deployment API.
DEFAULT_MODEL_ID = "qwen3-4b-instruct-2507-5f8261ad123d"
DEPLOYMENT = {
    "deployment_name": "第六轮密码微调结果",
    "fine_tune_job": "ft-202610051556-cc87",
    "fine_tune_output": "qwen3-4b-instruct-2507-ft-202610051556-cc87",
    "base_model": "qwen3-4b-instruct-2507",
    "workspace_id": "ws-avxkjb2tq5lq1gwm",
    "status": "RUNNING",
    "hyperparams": {
        "lora_rank": 16, "lora_alpha": 32, "lora_dropout": 0.005,
        "learning_rate": "1e-4", "n_epochs": 3, "batch_size": 128,
        "max_length": 4096, "lr_scheduler": "cosine",
    },
}


def load_jsonl(path: Path) -> list:
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def _norm_verdict(v) -> str:
    v = (v or "").strip().lower()
    if "confirm" in v:
        return "Confirm"
    if "reject" in v:
        return "Reject"
    return "?"


def run_detect(backend, records):
    preds = []
    for i, rec in enumerate(records, 1):
        for attempt in range(3):
            try:
                out = backend.detect(rec.get("code", ""))
                break
            except LLMError as e:
                print(f"  !! detect #{i} ({rec.get('id','?')[:40]}) error: {e}")
                out = {}
                time.sleep(2.0 * (attempt + 1))
        preds.append(out)
        gt = bool(rec["label"].get("vulnerable"))
        pv = bool(out.get("vulnerable"))
        flag = "OK" if gt == pv else "**"
        print(f"  detect #{i:2d} gt={gt!s:5} pred={pv!s:5} {flag}  {rec.get('id','?')[:52]}")
    return preds


def run_triage(backend, records):
    preds = []
    for i, rec in enumerate(records, 1):
        code, finding = rec.get("code", ""), rec.get("finding", "")
        for attempt in range(3):
            try:
                out = backend.triage(code, finding)
                break
            except LLMError as e:
                print(f"  !! triage #{i} ({rec.get('id','?')[:40]}) error: {e}")
                out = {}
                time.sleep(2.0 * (attempt + 1))
        preds.append(out)
        gt = rec["label"].get("verdict")
        pv = _norm_verdict(out.get("verdict"))
        flag = "OK" if pv == gt else "**"
        print(f"  triage #{i:2d} gt={gt:<7} pred={pv:<7} {flag}  {rec.get('id','?')[:48]}")
    return preds


def run_probes(backend, probes):
    rows = []
    for i, (gt, finding, code) in enumerate(probes):
        for attempt in range(3):
            try:
                out = backend.triage(code, finding)
                break
            except LLMError as e:
                print(f"  !! probe #{i} error: {e}")
                out = {}
                time.sleep(2.0 * (attempt + 1))
        pred = _norm_verdict(out.get("verdict"))
        name = (code.strip().splitlines()[0] if code.strip() else "")[:52]
        rows.append({"idx": i, "gt": gt, "pred": pred, "name": name,
                     "explanation": out.get("explanation", "")})
        flag = "OK" if pred == gt else "**"
        print(f"  probe #{i:2d} gt={gt:<7} pred={pred:<7} {flag}  {name}")
    return rows


def probe_summary(rows):
    n = len(rows)
    gtc = [r for r in rows if r["gt"] == "Confirm"]
    gtr = [r for r in rows if r["gt"] == "Reject"]
    cp = sum(1 for r in gtc if r["pred"] == "Confirm")
    fp = sum(1 for r in gtr if r["pred"] == "Confirm")
    ok = sum(1 for r in rows if r["pred"] == r["gt"])
    return {
        "n": n, "n_confirm_gt": len(gtc), "n_reject_gt": len(gtr),
        "confirm_recall": round(cp / len(gtc), 4) if gtc else None,
        "fpr": round(fp / len(gtr), 4) if gtr else None,
        "accuracy": round(ok / n, 4),
        "mismatches": [r for r in rows if r["pred"] != r["gt"]],
    }


def _short_id(s, n=46):
    return s if len(s) <= n else s[:n - 1] + "…"


def build_report(model_id, detect_recs, detect_preds, detect_metrics, static_preds, static_metrics,
                 triage_recs, triage_preds, triage_metrics, probe_rows, probe_m, started):
    L = []
    a = L.append
    a("# Round-6 最终评测报告（Final Test Set + Model Capability）\n")
    a(f"> 日期：{started}\n")
    a("> 模型：`" + model_id + "`（" + DEPLOYMENT["deployment_name"] + "）\n")
    a("")

    a("## 一、被测模型\n")
    a("| 项 | 值 |")
    a("|---|---|")
    a(f"| 部署模型 ID | `{model_id}` |")
    a(f"| 微调任务 | `{DEPLOYMENT['fine_tune_job']}`（{DEPLOYMENT['deployment_name']}） |")
    a(f"| 基座 | `{DEPLOYMENT['base_model']}`（新鲜基座，全量合并重训） |")
    a(f"| 部署状态 | {DEPLOYMENT['status']} |")
    a(f"| 工作空间 | `{DEPLOYMENT['workspace_id']}` |")
    hp = DEPLOYMENT["hyperparams"]
    a(f"| 训练超参 | LoRA rank={hp['lora_rank']} alpha={hp['lora_alpha']} dropout={hp['lora_dropout']}；"
      f"lr={hp['learning_rate']} epochs={hp['n_epochs']} batch={hp['batch_size']} "
      f"max_len={hp['max_length']}（{hp['lr_scheduler']}） |")
    a("")
    a("> 数据集：R6 全量合并重训（R5 基座 4122 条 + R6 新增 401 条，其中 `verified=true` 真实记录 79 条、"
      "真实 crypto 正例 30 条）。评测使用**冻结留出集** `data/round6/validation_frozen/`（训练不可见）。\n")

    a("## 二、最终测试集（冻结留出集）\n")

    # detect
    dm = detect_metrics
    a("### 2.1 Detect 切片（n=%d，漏洞 %d / 安全 %d）\n" % (
        dm["n"], sum(1 for r in detect_recs if r["label"].get("vulnerable")),
        sum(1 for r in detect_recs if not r["label"].get("vulnerable"))))
    a("| 系统 | recall | precision | f1 | accuracy | cwe_acc | tp/fp/fn/tn |")
    a("|---|---|---|---|---|---|---|")
    a(f"| llm (R6 微调) | {dm['recall']:.3f} | {dm['precision']:.3f} | {dm['f1']:.3f} "
      f"| {dm['accuracy']:.3f} | {dm['cwe_acc']} | {dm['tp']}/{dm['fp']}/{dm['fn']}/{dm['tn']} |")
    if static_metrics is not None:
        sm = static_metrics
        a(f"| static (Semgrep) | {sm['recall']:.3f} | {sm['precision']:.3f} | {sm['f1']:.3f} "
          f"| {sm['accuracy']:.3f} | {sm['cwe_acc']} | {sm['tp']}/{sm['fp']}/{sm['fn']}/{sm['tn']} |")
    a("")
    a("| # | 样本 | GT | Pred | CWE(Pred) | 判定 |")
    a("|---|---|---|---|---|---|")
    for i, (rec, p) in enumerate(zip(detect_recs, detect_preds), 1):
        gt = bool(rec["label"].get("vulnerable"))
        pv = bool(p.get("vulnerable"))
        ok = "✓" if gt == pv else "✗"
        gtc = rec["label"].get("cwe") or "—"
        pc = p.get("cwe") or "—"
        a(f"| {i} | `{_short_id(rec.get('id','?'))}` | {'漏洞' if gt else '安全'} ({gtc}) "
          f"| {'漏洞' if pv else '安全'} | {pc} | {ok} |")
    a("")

    # triage
    tm = triage_metrics
    a("### 2.2 Triage（domain）切片（n=%d，GT-Confirm %d / GT-Reject %d）\n" % (
        tm["n"], tm["gt_confirm"], tm["gt_reject"]))
    a("| 系统 | confirm_recall | fpr | accuracy |")
    a("|---|---|---|---|")
    a(f"| llm (R6 微调) | {tm['confirm_recall']:.3f} | {tm['fpr']:.3f} | {tm['accuracy']:.3f} |")
    a("| static（accept-all，系统①） | 1.000 | 1.000 | — |")
    a("")
    a("> `confirm_recall` 仅基于 %d 条 GT-Confirm，**只有计数意义，不做统计验收**（见 `benchmark_round6.yaml` 注释）。\n" % tm["gt_confirm"])
    a("| # | 样本 | GT | Pred | 判定 |")
    a("|---|---|---|---|---|")
    for i, (rec, p) in enumerate(zip(triage_recs, triage_preds), 1):
        gt = rec["label"].get("verdict")
        pv = _norm_verdict(p.get("verdict"))
        ok = "✓" if pv == gt else "✗"
        a(f"| {i} | `{_short_id(rec.get('id','?'))}` | {gt} | {pv} | {ok} |")
    a("")

    # probes
    a("## 三、模型能力测试（18 条真实探针）\n")
    a("| 指标 | 值 |")
    a("|---|---|")
    a(f"| n | {probe_m['n']}（GT-Confirm {probe_m['n_confirm_gt']} / GT-Reject {probe_m['n_reject_gt']}） |")
    a(f"| confirm_recall | {probe_m['confirm_recall']:.3f} |")
    a(f"| fpr | {probe_m['fpr']:.3f} |")
    a(f"| accuracy | {probe_m['accuracy']:.3f} |")
    a("")
    a("| # | GT | Pred | 样本首行 | 判定 |")
    a("|---|---|---|---|---|")
    for r in probe_rows:
        ok = "✓" if r["pred"] == r["gt"] else "✗"
        a(f"| {r['idx']} | {r['gt']} | {r['pred']} | `{_short_id(r['name'], 52)}` | {ok} |")
    if probe_m["mismatches"]:
        a("")
        a("**错分样本**：" + "、".join(f"#{r['idx']} (GT {r['gt']}→Pred {r['pred']})"
                                   for r in probe_m["mismatches"]))
    a("")

    # acceptance
    a("## 四、验收门槛对照\n")
    a("| 门槛 | 目标 | 实测 | 判定 |")
    a("|---|---|---|---|")
    a(f"| detect precision | > 0.54（R3/R4 基线） | {dm['precision']:.3f} | "
      f"{'✅' if dm['precision'] > 0.54 else '❌'} |")
    a(f"| domain fpr | ≤ 0.06（R5 目标） | {tm['fpr']:.3f} | "
      f"{'✅' if tm['fpr'] <= 0.06 else '❌'} |")
    a(f"| 18 探针 accuracy | ≥ 0.95 | {probe_m['accuracy']:.3f} | "
      f"{'✅' if probe_m['accuracy'] >= 0.95 else '❌'} |")
    a(f"| domain confirm_recall | 仅报告（n={tm['gt_confirm']}，无统计意义） | {tm['confirm_recall']:.3f} | — |")
    a("")

    a("## 五、结论与局限\n")
    a("- 本报告结果基于冻结留出集（detect n=19 / triage n=36）与 18 条探针，样本量小，"
      "尤其 domain 只有 4 条 GT-Confirm，`confirm_recall` 无统计意义。")
    a("- 真实 crypto 正例当前 30 条（< 50-100 门槛），**不得**将本结果解读为真实 crypto 漏洞泛化能力。")
    a("- detect 切片含 12 条安全加密代码（itsdangerous/passlib/python-rsa/PyJWT/PyCryptoDome/ecdsa/RC4-legacy），"
      "专门检验模型区分「安全用法 / 弱原语×安全 / 真漏洞」的能力。")
    a("- 证据文件：`benchmark_r6.json`（detect+domain 逐条预测）、`triage_probe_results_r6.json`（18 探针）。")
    a("")

    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-id", default=None)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--skip-static", action="store_true")
    args = ap.parse_args()

    model_id = args.model_id or DEFAULT_MODEL_ID
    backend = CloudBackend(model_id=model_id)  # api_key/base_url/workspace from env
    print(f"[*] backend: {type(backend).__name__} model={backend.model_id}")
    print(f"    base_url={backend.base_url}")

    started = time.strftime("%Y-%m-%d %H:%M:%S")

    detect_recs = load_jsonl(DETECT_PATH)
    triage_recs = load_jsonl(TRIAGE_PATH)
    probes = json.loads(PROBES_PATH.read_text(encoding="utf-8"))

    print(f"\n[*] FINAL TEST SET — detect slice (n={len(detect_recs)})")
    detect_preds = run_detect(backend, detect_recs)
    detect_metrics = _detect_metrics(detect_recs, detect_preds)

    print(f"\n[*] FINAL TEST SET — triage/domain slice (n={len(triage_recs)})")
    triage_preds = run_triage(backend, triage_recs)
    triage_metrics = _triage_metrics(triage_recs, triage_preds)

    print(f"\n[*] MODEL CAPABILITY — 18 grounded probes (n={len(probes)})")
    probe_rows = run_probes(backend, probes)
    probe_m = probe_summary(probe_rows)

    static_preds = static_metrics = None
    if not args.skip_static:
        print(f"\n[*] STATIC baseline (Semgrep, detect slice only)")
        static_preds = static_detect(detect_recs, RULES_DIR)
        static_metrics = _detect_metrics(detect_recs, static_preds)

    # ---- write artifacts ----
    args.out_dir.mkdir(parents=True, exist_ok=True)
    bench = {
        "model_id": model_id, "deployment": DEPLOYMENT, "started": started,
        "detect": {"metrics": detect_metrics, "preds": detect_preds},
        "domain": {"metrics": triage_metrics, "preds": triage_preds},
        "static_detect": {"metrics": static_metrics, "preds": static_preds} if static_metrics else None,
        "probes": {"summary": probe_m, "rows": probe_rows},
    }
    (args.out_dir / "benchmark_r6.json").write_text(
        json.dumps(bench, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.out_dir / "triage_probe_results_r6.json").write_text(
        json.dumps(probe_rows, indent=2, ensure_ascii=False), encoding="utf-8")
    report = build_report(model_id, detect_recs, detect_preds, detect_metrics,
                          static_preds, static_metrics, triage_recs, triage_preds,
                          triage_metrics, probe_rows, probe_m, started)
    (args.out_dir / "RESULTS.md").write_text(report, encoding="utf-8")

    print(f"\n[+] wrote {args.out_dir}/benchmark_r6.json")
    print(f"[+] wrote {args.out_dir}/triage_probe_results_r6.json")
    print(f"[+] wrote {args.out_dir}/RESULTS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
