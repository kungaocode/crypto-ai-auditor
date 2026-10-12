"""API and upload smoke tests for the CryptoAudit web application."""

from __future__ import annotations

import io
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from webapp.backend.app import app


SNIPPET = """\
import hashlib
import requests

key = b"0123456789abcdef"


def digest(data):
    return hashlib.md5(data).hexdigest()


def fetch(url):
    return requests.get(url, verify=False)
"""


def zip_payload(files: dict[str, str]) -> io.BytesIO:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, source in files.items():
            archive.writestr(name, source)
    payload.seek(0)
    return payload


class WebAppSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.feedback_dir = tempfile.TemporaryDirectory()
        cls.feedback_env = patch.dict(
            os.environ,
            {"CRYPTOAUDIT_FEEDBACK_DIR": cls.feedback_dir.name},
        )
        cls.feedback_env.start()
        app.testing = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.feedback_env.stop()
        cls.feedback_dir.cleanup()

    def test_frontend_and_catalog_are_served(self) -> None:
        index = self.client.get("/")
        self.assertEqual(index.status_code, 200)
        self.assertIn(b"CryptoAudit", index.data)
        self.assertIn(b"feedback-chip", index.data)

        script = self.client.get("/js/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"DOMContentLoaded", script.data)

        health = self.client.get("/api/health").get_json()
        self.assertTrue(health["ok"])
        self.assertEqual(health["static_engine"]["rules"]["total"], 13)
        self.assertTrue(health["feedback"]["enabled"])
        self.assertTrue(health["feedback"]["dataset"].endswith("submissions.jsonl"))

        rules = self.client.get("/api/rules").get_json()
        self.assertEqual(len(rules["rules"]), 13)

    def test_paste_audit_and_reports(self) -> None:
        response = self.client.post(
            "/api/audit",
            json={
                "code": SNIPPET,
                "filename": "sample.py",
                "model_mode": "mock",
                "generate_patches": True,
                "extended": True,
            },
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertGreaterEqual(result["summary"]["total_findings"], 3)

        audit_id = result["audit_id"]
        detail = self.client.get(f"/api/audits/{audit_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["result"]["audit_id"], audit_id)

        markdown = self.client.get(f"/api/audits/{audit_id}/report?format=md")
        self.assertEqual(markdown.status_code, 200)
        self.assertIn(b"# ", markdown.data)

        report_json = self.client.get(f"/api/audits/{audit_id}/report?format=json")
        self.assertEqual(report_json.status_code, 200)
        self.assertEqual(json.loads(report_json.data)["audit_id"], audit_id)

    def test_single_file_upload(self) -> None:
        response = self.client.post(
            "/api/audit/upload",
            data={
                "files": (io.BytesIO(SNIPPET.encode()), "upload.py"),
                "model_mode": "mock",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["target"]["file_count"], 1)
        self.assertEqual(result["target"]["primary"], "upload.py")

    def test_zip_upload_from_files_field(self) -> None:
        response = self.client.post(
            "/api/audit/upload",
            data={
                "files": (zip_payload({"pkg/sample.py": SNIPPET}), "sample.zip"),
                "model_mode": "mock",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["target"]["file_count"], 1)
        self.assertEqual(result["target"]["primary"], "sample.py")

    def test_zip_upload_from_archive_field(self) -> None:
        response = self.client.post(
            "/api/audit/upload",
            data={
                "archive": (zip_payload({"pkg/sample.py": SNIPPET}), "sample.zip"),
                "model_mode": "mock",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["target"]["file_count"], 1)

    def test_feedback_records_source_for_retraining(self) -> None:
        response = self.client.post(
            "/api/audit",
            json={
                "code": SNIPPET,
                "filename": "feedback_sample.py",
                "model_mode": "mock",
            },
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertTrue(result["feedback"]["enabled"])
        self.assertEqual(result["feedback"]["stored_samples"], 1)

        dataset = Path(self.feedback_dir.name) / "submissions.jsonl"
        records = [
            json.loads(line)
            for line in dataset.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        record = next(
            item
            for item in records
            if item["audit_id"] == result["audit_id"]
        )
        self.assertEqual(record["code"], SNIPPET)
        self.assertEqual(record["file"], "feedback_sample.py")
        self.assertEqual(record["review_status"], "pending")
        self.assertFalse(record["verified"])
        self.assertFalse(record["training_ready"])
        self.assertEqual(
            record["code_sha256"],
            hashlib.sha256(SNIPPET.encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
