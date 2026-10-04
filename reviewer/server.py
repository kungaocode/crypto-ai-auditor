"""Zero-dependency HTTP server for the Round-6 real-crypto reviewer."""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reviewer.store import ReviewStore, ReviewStoreError


STATIC_DIR = Path(__file__).resolve().parent / "static"
_MAX_BODY_BYTES = 512 * 1024


def _handler_for(store: ReviewStore):
    class ReviewHandler(BaseHTTPRequestHandler):
        server_version = "CryptoReviewer/1.0"

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/health":
                self._send_json(200, {"ok": True})
                return
            if path == "/api/session":
                self._handle(store.session)
                return
            if path.startswith("/api/"):
                self._send_json(404, {"error": f"unknown API route: {path}"})
                return
            self._serve_static(path)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/review":
                self._handle(lambda: store.review(self._read_json()))
                return
            if path == "/api/export":
                self._handle(store.export)
                return
            self._send_json(404, {"error": f"unknown API route: {path}"})

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            prefix = "/api/review/"
            if path.startswith(prefix):
                item_id = unquote(path[len(prefix):])
                self._handle(lambda: store.clear(item_id))
                return
            self._send_json(404, {"error": f"unknown API route: {path}"})

        def _handle(self, action) -> None:
            try:
                payload = action()
            except ReviewStoreError as exc:
                self._send_json(400, {"error": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:  # pragma: no cover - local safety net
                self._send_json(500, {"error": f"internal server error: {exc}"})
            else:
                self._send_json(200, {"ok": True, "result": payload})

        def _read_json(self):
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ReviewStoreError("invalid Content-Length") from exc
            if length <= 0 or length > _MAX_BODY_BYTES:
                raise ReviewStoreError("invalid request body size")
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReviewStoreError("request body must be valid UTF-8 JSON") from exc

        def _serve_static(self, request_path: str) -> None:
            relative = "index.html" if request_path == "/" else request_path.lstrip("/")
            if relative not in {"index.html", "app.js", "styles.css"}:
                self._send_json(404, {"error": "not found"})
                return
            path = STATIC_DIR / relative
            if not path.is_file():
                self._send_json(404, {"error": f"missing static asset: {relative}"})
                return
            body = path.read_bytes()
            content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in (
                "application/javascript",
                "text/javascript",
            ):
                content_type += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            print(f"[reviewer] {self.address_string()} {fmt % args}")

    return ReviewHandler


def build_server(
    store: ReviewStore,
    host: str = "127.0.0.1",
    port: int = 8766,
) -> ThreadingHTTPServer:
    """Create a threaded HTTP server without starting it."""
    return ThreadingHTTPServer((host, port), _handler_for(store))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the local human-review app for Round-6 real crypto candidates"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--reviewer", default="reviewer", help="review identity (default: reviewer)")
    parser.add_argument(
        "--candidates",
        default=None,
        help="override candidate JSONL path (enriched file is preferred by default)",
    )
    parser.add_argument("--open", action="store_true", help="open the app in the default browser")
    args = parser.parse_args(argv)

    try:
        store = ReviewStore(ROOT, args.reviewer, candidates_path=args.candidates)
        session = store.session()
    except (ReviewStoreError, ValueError) as exc:
        print(f"[reviewer] cannot start: {exc}")
        return 1

    try:
        server = build_server(store, args.host, args.port)
    except OSError as exc:
        print(f"[reviewer] cannot listen on {args.host}:{args.port}: {exc}")
        print("[reviewer] choose another port with --port.")
        return 1

    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{display_host}:{actual_port}"
    print(f"[reviewer] {session['total']} candidates loaded from {session['candidates_path']}")
    print(f"[reviewer] reviewer={store.reviewer}  url={url}")
    print("[reviewer] press Ctrl+C to stop")

    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[reviewer] stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
