import unittest

from services.stable_submission import (
    apply_stage_submissions,
    consume_response_submissions,
    merge_inline_submission_payloads,
    preserve_submission_state,
    _merge_reviews,
    _page_items,
)


class StageStub:
    def __init__(self, stage_num):
        self.stage_num = stage_num
        self.compressed_summary = {}
        self.findings = {}


class StableSubmissionTests(unittest.TestCase):
    def test_consumes_inline_route_submissions(self):
        stage = StageStub(1)
        response = {
            "stage_summary": "ok",
            "architecture_info": {"routes": []},
            "stable_submissions": {
                "routes": [
                    {
                        "method": "GET",
                        "path": "/api/users",
                        "source": "app/routes.py",
                        "handler": "list_users",
                    }
                ]
            },
        }

        cleaned, stats = consume_response_submissions(stage, response)
        merged = apply_stage_submissions(stage, cleaned)

        self.assertNotIn("stable_submissions", cleaned)
        self.assertEqual(stats["routes"]["total"], 1)
        self.assertEqual(stage.compressed_summary["stable_submissions"]["routes"][0]["path"], "/api/users")
        self.assertEqual(merged["architecture_info"]["routes"][0]["path"], "/api/users")

    def test_consumes_findings_and_reviews(self):
        stage = StageStub(3)
        response = {
            "stage_summary": "ok",
            "vulnerabilities": [],
            "stable_submissions": {
                "findings": [
                    {
                        "title": "SQL injection",
                        "vuln_type": "SQL injection",
                        "file_path": "app.py",
                        "endpoint": "GET /q",
                        "description": "input reaches dynamic SQL",
                    }
                ],
                "reviews": [
                    {
                        "finding_index": 0,
                        "verification_status": "confirmed",
                        "reviewed_severity": "High",
                        "verification_reason": "evidence complete",
                    }
                ],
            },
        }

        cleaned, stats = consume_response_submissions(stage, response)
        merged = apply_stage_submissions(stage, cleaned)

        self.assertEqual(stats["findings"]["total"], 1)
        self.assertEqual(stats["reviews"]["total"], 1)
        self.assertEqual(len(merged["vulnerabilities"]), 1)
        self.assertEqual(merged["vulnerabilities"][0]["verification_status"], "confirmed")

    def test_review_can_match_by_finding_id(self):
        stage = StageStub(3)
        stage.compressed_summary = {
            "stable_submissions": {
                "reviews": [
                    {
                        "finding_index": 9,
                        "finding_id": "finding-a",
                        "verification_status": "rejected",
                        "verification_reason": "not reachable",
                    }
                ]
            }
        }
        response = {
            "vulnerabilities": [
                {"id": "finding-a", "title": "A"},
                {"id": "finding-b", "title": "B"},
            ]
        }

        merged = apply_stage_submissions(stage, response)

        self.assertEqual(merged["vulnerabilities"][0]["verification_status"], "rejected")
        self.assertNotIn("verification_status", merged["vulnerabilities"][1])

    def test_merges_inline_submission_payloads(self):
        base = {
            "stage_summary": "a",
            "stable_submissions": {
                "routes": [{"method": "GET", "path": "/a", "source": "a.py"}]
            },
        }
        incoming = {
            "stage_summary": "b",
            "stable_submissions": {
                "routes": [{"method": "POST", "path": "/b", "source": "b.py"}]
            },
        }

        merged = merge_inline_submission_payloads(base, incoming)

        self.assertEqual(len(merged["stable_submissions"]["routes"]), 2)

    def test_reviews_merge_by_finding_id_before_index(self):
        existing = [
            {
                "finding_index": 0,
                "finding_id": "finding-a",
                "verification_status": "uncertain",
            }
        ]
        incoming = [
            {
                "finding_index": 4,
                "finding_id": "finding-a",
                "verification_status": "confirmed",
                "verification_reason": "evidence improved",
            },
            {
                "finding_index": 0,
                "finding_id": "finding-b",
                "verification_status": "rejected",
            },
        ]

        merged = _merge_reviews(existing, incoming)

        self.assertEqual(len(merged), 2)
        by_id = {item["finding_id"]: item for item in merged}
        self.assertEqual(by_id["finding-a"]["finding_index"], 4)
        self.assertEqual(by_id["finding-a"]["verification_status"], "confirmed")
        self.assertEqual(by_id["finding-b"]["verification_status"], "rejected")

    def test_page_items_clamps_page_size(self):
        page = _page_items([{"id": index} for index in range(250)], page=1, page_size=999)

        self.assertEqual(page["page_size"], 200)
        self.assertEqual(len(page["items"]), 200)
        self.assertTrue(page["has_more"])

    def test_preserve_submission_state_when_summary_replaced(self):
        stage = StageStub(1)
        stage.compressed_summary = {
            "stable_submissions": {
                "routes": [{"method": "GET", "path": "/kept"}]
            }
        }

        summary = preserve_submission_state(stage, {"coverage": {"scanned_chunk_count": 3}})

        self.assertEqual(summary["coverage"]["scanned_chunk_count"], 3)
        self.assertEqual(summary["stable_submissions"]["routes"][0]["path"], "/kept")


if __name__ == "__main__":
    unittest.main()
