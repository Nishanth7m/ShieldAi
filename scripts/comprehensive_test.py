"""
ShieldAI comprehensive test runner.

Runs structure/config checks + unittest suite, and writes a markdown report.

Usage:
  .venv\\Scripts\\python.exe scripts\\comprehensive_test.py
"""

from __future__ import annotations

import compileall
import os
import pathlib
import sys
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    # Ensure project root is importable for tests (config.py, main.py, etc.)
    sys.path.insert(0, str(ROOT))


class CheckResult:
    def __init__(self, status: str, name: str, detail: str) -> None:
        self.status = status  # PASS/FAIL/WARN
        self.name = name
        self.detail = detail


def check_structure() -> list[CheckResult]:
    required = [
        "main.py",
        "config.py",
        "requirements.txt",
        ".env.example",
        ".gitignore",
        "README.md",
        "agents",
        "api",
        "database",
        "static",
        "data",
    ]
    missing = [p for p in required if not (ROOT / p).exists()]
    if missing:
        return [CheckResult("FAIL", "Project structure", f"Missing required paths: {missing}")]
    return [CheckResult("PASS", "Project structure", "All required files/folders exist.")]


def check_python_compile() -> list[CheckResult]:
    # Avoid compiling the venv.
    import re

    ok = compileall.compile_dir(str(ROOT), quiet=1, rx=re.compile(r".*\\\.venv\\.*"))
    if ok:
        return [CheckResult("PASS", "Python syntax", "All Python files compile successfully.")]
    return [CheckResult("FAIL", "Python syntax", "One or more Python files failed to compile (see console output).")]


def check_config_sanity() -> list[CheckResult]:
    out: list[CheckResult] = []
    try:
        from config import ATTACK_PATTERNS, get_settings, validate_weights  # type: ignore
        import re

        # Regex compile check
        for p in ATTACK_PATTERNS:
            re.compile(p["regex"])
        out.append(CheckResult("PASS", "Attack pattern regex", f"Compiled {len(ATTACK_PATTERNS)} regex patterns."))

        s = get_settings()
        # Threshold bounds
        bad = []
        for name in ["pattern_threshold", "anomaly_threshold", "semantic_threshold", "final_block_threshold"]:
            v = float(getattr(s, name))
            if not (0.0 <= v <= 1.0):
                bad.append((name, v))
        if bad:
            out.append(CheckResult("FAIL", "Threshold values", f"Out-of-range thresholds: {bad}"))
        else:
            out.append(CheckResult("PASS", "Threshold values", "All thresholds within [0.0, 1.0]."))

        try:
            validate_weights(s)
            out.append(CheckResult("PASS", "Ensemble weights", "Weights validated (sum ~1.0, non-negative)."))
        except Exception as e:
            out.append(CheckResult("FAIL", "Ensemble weights", f"validate_weights failed: {e!r}"))

        # Python version note (repo doc says 3.11; env may differ)
        if sys.version_info[:2] != (3, 11):
            out.append(
                CheckResult(
                    "WARN",
                    "Python version",
                    f"Running on Python {sys.version.split()[0]} (project context mentions 3.11). Validate deployment runtime.",
                )
            )
        else:
            out.append(CheckResult("PASS", "Python version", "Running on Python 3.11 as expected."))
    except Exception as e:
        out.append(CheckResult("FAIL", "Config sanity", f"Config checks failed: {e!r}"))
    return out


def run_unittests() -> tuple[list[CheckResult], int]:
    # Isolate DB/model paths so tests don't touch real data.
    tmp = tempfile.TemporaryDirectory()
    os.environ.setdefault("DATABASE_PATH", str(pathlib.Path(tmp.name) / "test.db"))
    os.environ.setdefault("MODEL_PATH", str(pathlib.Path(tmp.name) / "model.joblib"))
    os.environ.setdefault("ANTHROPIC_API_KEY", "")
    os.environ.setdefault("AUTH_SECRET_KEY", "test-secret")

    suite = unittest.TestLoader().discover(str(ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    checks: list[CheckResult] = []
    if result.wasSuccessful():
        checks.append(CheckResult("PASS", "Unit test suite", f"All tests passed ({result.testsRun} tests)."))
        exit_code = 0
    else:
        checks.append(
            CheckResult(
                "FAIL",
                "Unit test suite",
                f"Failures={len(result.failures)}, Errors={len(result.errors)} out of {result.testsRun} tests.",
            )
        )
        exit_code = 1

    tmp.cleanup()
    return checks, exit_code


def write_report(results: list[CheckResult], *, path: pathlib.Path) -> None:
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    warned = sum(1 for r in results if r.status == "WARN")

    lines = []
    lines.append("# ShieldAI Test Report")
    lines.append("")
    lines.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    for r in results:
        icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "WARN": "⚠️  WARN"}[r.status]
        lines.append(f"- {icon} - {r.name}: {r.detail}")
    lines.append("")
    lines.append("## Test Summary")
    lines.append("")
    lines.append(f"- Total: {len(results)}")
    lines.append(f"- Passed: {passed}")
    lines.append(f"- Failed: {failed}")
    lines.append(f"- Warnings: {warned}")
    lines.append("")
    lines.append("## Deployment Readiness Status")
    lines.append("")
    lines.append("**YES**" if failed == 0 else "**NO**")
    lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    results: list[CheckResult] = []
    results += check_structure()
    results += check_python_compile()
    results += check_config_sanity()
    unit_results, exit_code = run_unittests()
    results += unit_results

    report_path = ROOT / "TEST_REPORT.md"
    write_report(results, path=report_path)
    print(f"\nWrote report: {report_path}\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

