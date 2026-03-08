# Examples

## Scenario 1: Hospitality workflow cues
Input: `examples/scenario_hospitality/input.json`

Run:
```bash
trust-surface examples/scenario_hospitality/input.json --out examples/output/hospitality.json --risk-type impersonation
```

Expected output snippet (from local run):
```text
confidence=67
```

## Scenario 2: Boilerplate-only evidence
Input: `examples/scenario_boilerplate/input.json`

Run:
```bash
trust-surface examples/scenario_boilerplate/input.json --out examples/output/boilerplate.json --risk-type impersonation
```

Expected output snippet (from local run):
```text
confidence=47
```

## Sample dataset
- `examples/sample_data/manifest.jsonl` (sanitized, offline)
