# Contributing

Thanks for improving Agentic Risk Scan.

## Development

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-ai-pr-bot --fail-on none
```

## Rule Changes

Rule PRs should include:

- A minimal unsafe fixture or test.
- A safe fixture when the rule could plausibly false-positive.
- Clear remediation text.
- Stable rule IDs.

Keep the scanner dependency-free unless there is a strong reason to change that
constraint.
