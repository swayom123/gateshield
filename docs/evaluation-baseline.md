# Local Evaluation Baseline

This report records a run of fixture set `gateshield-security-v1`, version 1, on 2026-10-10. All inputs are synthetic and local. Evaluation uses the deterministic input inspector, active built-in policy definitions, and an in-memory SQLite tool registry. It makes no provider or external network calls.

## Detection and enforcement

| Measure | Result | Denominator | Conditions |
| --- | ---: | ---: | --- |
| Prompt injection true positive rate | 6/6 (100%) | 6 labeled positive | Direct, retrieved, mixed, base64, percent encoded, and zero-width samples |
| Prompt injection false positive rate | 1/5 (20%) | 5 labeled negative | One benign security discussion is detected because it contains an instruction override phrase |
| Secret detection recall | 2/2 (100%) | 2 labeled positive | Synthetic credential assignment and token-shaped string |
| Secret detection false positive rate | 0/9 (0%) | 9 labeled negative | Remaining text fixtures |
| Policy outcomes matching fixture labels | 10/11 (90.9%) | 11 | Built-in policies evaluated using actual detector output; labels mark expected block/allow |
| Tool authorization outcomes matching fixture labels | 4/4 (100%) | 4 | In-memory registered schema, agent tool/resource scope, invalid arguments, and unknown tool |

These small fixture results describe only the checked-in examples. They do not estimate production detection coverage. In particular, the benign security discussion false positive should remain visible while detector rules are tuned.

## Local benchmark

Five measured iterations per operation after starting the local services; provider stub connection was warmed before measurement. The benchmark ran on Python 3.14.4, Linux 7.0.0-38-generic, x86_64, glibc 2.43. Values are median wall time in milliseconds:

| Operation | Median | Samples |
| --- | ---: | ---: |
| Gateway local overhead (inspection plus policy) | 1.601 | 5 |
| Input inspection | 0.027 | 5 |
| Policy evaluation | 1.346 | 5 |
| Tool authorization | 2.394 | 5 |
| Provider latency, loopback HTTP stub | 42.005 | 5 |

This is a smoke benchmark on SQLite in-memory records in one process. The stub uses loopback HTTP and its latency does not represent a real provider or production deployment. Five samples are insufficient for a performance target or capacity claim. Reproduce with `python scripts/benchmark_security.py --iterations 100` and retain the emitted environment and methodology with any later report.

## Analyst feedback

Feedback records can use `fixtures/analyst_feedback.schema.json` with labels `TRUE_POSITIVE`, `FALSE_POSITIVE`, `EXPECTED`, and `UNKNOWN`. Feedback is evaluation metadata only; this tooling does not modify detector rules, policies, or model weights.
