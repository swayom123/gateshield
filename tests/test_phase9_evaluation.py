import pytest

from scripts.evaluate_security import evaluate


@pytest.mark.asyncio
async def test_local_evaluator_reports_labeled_denominators_and_tool_results():
    report = await evaluate()

    assert report["fixture_set"] == "gateshield-security-v1"
    assert report["fixture_version"] == 1
    assert "No provider or external network calls" in report["methodology"]
    assert report["metrics"]["prompt_injection"]["true_positive_rate"]["denominator"] == 6
    assert report["metrics"]["prompt_injection"]["false_positive_rate"]["denominator"] == 5
    assert report["metrics"]["secret_detection"]["recall"]["denominator"] == 2
    assert report["metrics"]["policy_enforcement"]["denominator"] == len(report["cases"])
    assert report["metrics"]["tool_authorization"]["denominator"] == len(report["tool_cases"])
