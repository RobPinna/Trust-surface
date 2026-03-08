# Design Decisions

## Decision 1: Keep FastAPI app structure stable
- Choice: preserve existing `app/` runtime layout to avoid regressions.
- Why: project already has end-to-end behavior and domain logic coupled to templates/connectors.
- Tradeoff: full package migration is incremental rather than immediate.

## Decision 2: Add typed public package for reusable scoring
- Choice: introduce `src/operational_leverage_framework` (internal package name) with explicit `core/io/models/cli`.
- Why: provide a clean public API boundary for portfolio usage and offline demos.
- Tradeoff: temporary dual-path imports (`app/services` and package wrappers).

## Decision 3: Deterministic offline examples
- Choice: examples use local JSON evidence inputs and deterministic scoring.
- Why: reproducible outputs for reviewers without connector/API dependencies.
- Tradeoff: examples represent a narrow subset of full workflow complexity.

## Decision 4: Quality gates with scoped mypy
- Choice: enforce Ruff/pytest globally and mypy on typed boundary modules.
- Why: practical maintainability without blocking on complete typing of all legacy paths.
- Tradeoff: some deeper modules remain outside strict type coverage.

## Decision 5: Standardize local launcher
- Choice: use `python scripts/run.py web` as the primary local entrypoint.
- Why: one predictable cross-platform startup command for GitHub users.
- Tradeoff: launcher logic is centralized in a Python wrapper script.
