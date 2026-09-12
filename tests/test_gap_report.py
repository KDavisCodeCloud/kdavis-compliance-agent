from compliance.gap_report import FRAMEWORK_NAME, build_gap_report


class TestBuildGapReport:
    def test_all_controls_pass_with_no_relevant_findings(self):
        report = build_gap_report([{"title": "Stopped instance still paying for storage"}])

        assert report["framework"] == FRAMEWORK_NAME
        assert report["controls_assessed"] == 4
        assert report["readiness_score"] == 100
        assert all(c["status"] == "PASS" for c in report["controls"])

    def test_readiness_score_reflects_partial_failures(self):
        findings = [
            {"title": "Root account has no MFA"},
            {"title": "Access key not rotated in 200 days"},
        ]
        report = build_gap_report(findings)

        statuses = {c["control_id"]: c["status"] for c in report["controls"]}
        assert statuses["1.4"] == "PASS"
        assert statuses["1.5"] == "FAIL"
        assert statuses["1.10"] == "PASS"
        assert statuses["1.14"] == "FAIL"
        assert report["readiness_score"] == 50

    def test_includes_coverage_note_and_documentation_checklist(self):
        report = build_gap_report([])

        assert "4" in report["coverage_note"]
        assert "62" in report["coverage_note"]
        assert len(report["documentation_checklist"]) == 3
        assert all(item["status"] == "cannot_verify_from_scan" for item in report["documentation_checklist"])

    def test_every_control_reports_its_security_hub_id_and_caveat_shape(self):
        report = build_gap_report([])

        for control in report["controls"]:
            assert control["security_hub_id"]
            assert isinstance(control["exact_match"], bool)

    def test_accepts_a_different_framework_via_optional_kwargs(self):
        """Added for Azure: a second CIS mapping (e.g. a future
        compliance/cis_azure_mapping.py) reuses this same function via
        these optional kwargs rather than duplicating the readiness-
        score/coverage-note logic. Defaults keep every AWS test above
        passing unchanged."""
        fake_controls = [
            {
                "control_id": "9.1",
                "security_hub_id": "FAKE.1",
                "title": "Fake control",
                "exact_match": True,
                "caveat": None,
                "match": lambda findings: len(findings) == 0,
            }
        ]
        report = build_gap_report([], framework_name="Fake Framework v1", controls=fake_controls, total_controls=10)

        assert report["framework"] == "Fake Framework v1"
        assert report["controls_assessed"] == 1
        assert report["controls_total_in_framework"] == 10
        assert report["readiness_score"] == 100
        assert "Fake Framework v1" in report["coverage_note"]
        assert "10" in report["coverage_note"]
