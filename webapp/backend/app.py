"""Flask application for the AI-assisted cryptographic code security auditor."""

from __future__ import annotations

import json
import sys
from collections import OrderedDict
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webapp.backend import config, feedback, service, uploads  # noqa: E402
from webapp.backend.rules_catalog import catalog_stats, load_catalog  # noqa: E402
from webapp.backend.scanners import semgrep_path  # noqa: E402

VERSION = "1.0.0"
MAX_CODE_CHARS = 300_000
RECENT_LIMIT = 30

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = config.max_upload_bytes() + 4 * 1024 * 1024
app.config["JSON_AS_ASCII"] = False

_recent: "OrderedDict[str, dict]" = OrderedDict()


def remember(result: dict) -> None:
    _recent[result["audit_id"]] = result
    _recent.move_to_end(result["audit_id"])
    while len(_recent) > RECENT_LIMIT:
        _recent.popitem(last=False)


def _options(options: dict) -> dict:
    model_mode = str(options.get("model_mode") or "auto").lower()
    return {
        "model_mode": model_mode,
        "generate_patches": bool(options.get("generate_patches", True)),
        "extended": bool(options.get("extended", False)),
    }


def _execute(staged: uploads.StagedAudit, options: dict) -> dict:
    resolved = _options(options)
    try:
        result = service.run_audit(
            staged.sources,
            staged.root,
            config.RULES_DIR,
            **resolved,
        )
        result["upload"] = {"skipped": staged.skipped}
        result["feedback"] = feedback.record_audit(staged.sources, result, resolved)
    finally:
        staged.cleanup()
    remember(result)
    return result


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(config.FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def static_assets(filename: str):
    return send_from_directory(config.FRONTEND_DIR, filename)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    catalog = load_catalog(config.RULES_DIR)
    return jsonify(
        {
            "ok": True,
            "service": "ai-crypto-code-security-auditor",
            "version": VERSION,
            "model": config.public_model_state(),
            "static_engine": {
                "semgrep_available": bool(semgrep_path()),
                "rules": catalog_stats(catalog),
            },
            "feedback": feedback.public_state(),
            "limits": {
                "max_upload_mb": config.max_upload_bytes() // (1024 * 1024),
                "max_files": uploads.MAX_FILES,
            },
        }
    )


@app.get("/api/rules")
def rules():
    catalog = load_catalog(config.RULES_DIR)
    return jsonify({"ok": True, "stats": catalog_stats(catalog), "rules": catalog})


@app.get("/api/audits")
def recent_audits():
    items = []
    for audit_id, result in reversed(_recent.items()):
        items.append(
            {
                "audit_id": audit_id,
                "created_at": result.get("created_at"),
                "target": result.get("target", {}).get("primary"),
                "file_count": result.get("target", {}).get("file_count", 0),
                "score": result.get("summary", {}).get("risk", {}).get("score", 0),
                "level": result.get("summary", {}).get("risk", {}).get("level", "INFO"),
                "total_findings": result.get("summary", {}).get("total_findings", 0),
            }
        )
    return jsonify({"ok": True, "audits": items})


@app.get("/api/audits/<audit_id>")
def audit_detail(audit_id: str):
    result = _recent.get(audit_id)
    if result is None:
        return jsonify({"ok": False, "error": "审计结果已过期或不存在。"}), 404
    return jsonify({"ok": True, "result": result})


@app.get("/api/audits/<audit_id>/report")
def audit_report(audit_id: str):
    result = _recent.get(audit_id)
    if result is None:
        return jsonify({"ok": False, "error": "审计结果已过期或不存在。"}), 404
    fmt = (request.args.get("format") or "md").lower()
    if fmt == "json":
        body = json.dumps(result, ensure_ascii=False, indent=2)
        return app.response_class(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit-{audit_id}.json"'},
        )
    body = service.build_markdown_report(result)
    return app.response_class(
        body,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="audit-{audit_id}.md"'},
    )


@app.post("/api/audit")
def audit_code():
    payload = request.get_json(silent=True) or {}
    code = payload.get("code")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"ok": False, "error": "请提供待审计的代码。"}), 400
    if len(code) > MAX_CODE_CHARS:
        return jsonify({"ok": False, "error": "代码过长，请拆分后审计。"}), 400
    staged = uploads.stage_code(code, payload.get("filename") or "snippet.py")
    result = _execute(staged, payload)
    return jsonify({"ok": True, "result": result})


@app.post("/api/audit/upload")
def audit_upload():
    files = request.files.getlist("files")
    archive = request.files.get("archive")
    staged = uploads.stage_uploads(files, archive)
    result = _execute(
        staged,
        {
            "model_mode": request.form.get("model_mode", "auto"),
            "generate_patches": request.form.get("generate_patches", "true").lower() != "false",
            "extended": request.form.get("extended", "false").lower() == "true",
        },
    )
    return jsonify({"ok": True, "result": result})


@app.post("/api/report")
def render_report():
    payload = request.get_json(silent=True) or {}
    result = payload.get("result")
    if not isinstance(result, dict) or "summary" not in result:
        return jsonify({"ok": False, "error": "缺少审计结果。"}), 400
    fmt = str(payload.get("format") or "md").lower()
    if fmt == "json":
        return app.response_class(
            json.dumps(result, ensure_ascii=False, indent=2),
            mimetype="application/json",
        )
    return app.response_class(service.build_markdown_report(result), mimetype="text/markdown")


@app.post("/analyze")
def legacy_analyze():
    """Compatibility shim for the original two-field prototype."""
    payload = request.get_json(silent=True) or {}
    code = payload.get("code")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"result": "No code provided"}), 400
    staged = uploads.stage_code(code, "snippet.py")
    result = _execute(staged, payload)
    return jsonify({"result": result})


# ---------------------------------------------------------------------------
# Errors and headers
# ---------------------------------------------------------------------------

@app.errorhandler(config.ConfigError)
@app.errorhandler(service.AuditError)
@app.errorhandler(uploads.UploadError)
def handle_bad_request(error):
    return jsonify({"ok": False, "error": str(error)}), 400


@app.errorhandler(413)
def handle_too_large(_error):
    return jsonify({"ok": False, "error": "上传内容超过大小上限。"}), 413


@app.errorhandler(404)
def handle_missing(error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "接口不存在。"}), 404
    return error, 404


@app.errorhandler(500)
def handle_server_error(error):
    return jsonify({"ok": False, "error": f"服务端异常：{error}"}), 500


@app.after_request
def set_headers(response):
    if request.path.startswith("/api/") or request.path == "/analyze":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/<path:_any>", methods=["OPTIONS"])
@app.route("/analyze", methods=["OPTIONS"])
def preflight(_any: str = ""):
    return ("", 204)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the CryptoAudit web application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
