## Summary

## Rule impact

- [ ] Adds or changes scanner behavior.
- [ ] Includes a minimal unsafe test or fixture.
- [ ] Includes a safe test when false positives are plausible.
- [ ] Updates rule docs or README when user-facing behavior changes.

## Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-ai-pr-bot --fail-on none
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/safe-agent-workflow --fail-on high
```

