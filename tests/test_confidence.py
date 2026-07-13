import pytest
from src.confidence import score_confidence, _score_freshness, _score_completeness
from src.models import ToolResult


class TestConfidenceScoring:
    def test_empty_results(self):
        assert score_confidence([], "ioc_lookup") == 0.0

    def test_single_error_result(self):
        r = ToolResult(source="virustotal", error="API Error", data={})
        assert score_confidence([r], "ioc_lookup") == 0.0

    def test_multiple_good_results_boost_confidence(self):
        r1 = ToolResult(source="virustotal", data={"malicious": 5, "total_engines": 70, "last_analysis_date": 2000000000})
        r2 = ToolResult(source="abuseipdb", data={"abuse_confidence_score": 95, "total_reports": 50})
        score = score_confidence([r1, r2], "ioc_lookup")
        assert 0.0 < score <= 1.0

    def test_virustotal_reliability_higher_than_otx(self):
        vt = ToolResult(source="virustotal", data={"malicious": 5, "total_engines": 70, "last_analysis_date": 2000000000})
        otx = ToolResult(source="otx", data={"malicious": 5, "total_engines": 70, "last_analysis_date": 2000000000})
        score_vt = score_confidence([vt], "ioc_lookup")
        score_otx = score_confidence([otx], "ioc_lookup")
        assert score_vt > score_otx

    def test_fresh_data_scores_higher(self):
        old = ToolResult(source="virustotal", data={"malicious": 5, "total_engines": 70, "last_analysis_date": 1000000000})
        fresh = ToolResult(source="virustotal", data={"malicious": 5, "total_engines": 70, "last_analysis_date": 2000000000})
        assert _score_freshness(fresh) > _score_freshness(old)

    def test_completeness_ioc_lookup(self):
        complete = ToolResult(source="virustotal", data={"malicious": 5, "total_engines": 70})
        partial = ToolResult(source="virustotal", data={"malicious": 5})
        assert _score_completeness(complete, "ioc_lookup") > _score_completeness(partial, "ioc_lookup")

    def test_completeness_exposure_check(self):
        with_cves = ToolResult(source="nvd", data={"cves": [{"id": "CVE-2023-1"}], "total_results": 1})
        empty = ToolResult(source="nvd", data={})
        assert _score_completeness(with_cves, "exposure_check") > _score_completeness(empty, "exposure_check")
