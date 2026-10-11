# Contributing to SentinelAI

SentinelAI is a **defensive cybersecurity research project**. All
contributions must respect that scope.

## Defensive-only policy (non-negotiable)

Contributions will be rejected if they add:

- offensive tooling of any kind (attack generation, scanning, packet
  injection, exploit/malware code, credential handling);
- live packet capture / sniffing;
- real firewall or network modification, or any automatic blocking;
- evasion, persistence, or unauthorized-access functionality;
- private or unlicensed datasets;
- secrets, credentials, or personal data of any kind.

## Development expectations

1. **Tests are required** for behavior changes. Run the full suite
   before submitting:
   ```powershell
   python -m pytest tests -q
   ```
   All tests must pass; do not delete, weaken, or skip existing tests.
2. **Respect the safety boundaries** enforced by `tests/validation/`
   (no write-SQL in the dashboard, no network APIs in `src/network/`,
   DRY_RUN invariants, parameterized SQL). New code must keep them
   green.
3. **No fabrication:** never hard-code or invent metrics, dataset
   statistics, or results. Reports must come from real runs.
4. **Reproducibility:** keep `random_state=42` and the documented
   configuration (`config/model_config.py`) unless the change is
   explicitly justified and documented.
5. **Data hygiene:** never commit datasets (`data/raw/`,
   `data/processed/`), the runtime database, logs, `.env`, `.venv`, or
   model binaries — they are git-ignored by design.
6. **Style:** match the existing beginner-friendly, documented style;
   keep public functions typed where practical.

## Reporting issues

Include the exact command, the actual output, and the environment
(Windows version, Python version). Do not include dataset contents,
PCAP payloads, or any sensitive network information in issue reports.

## License

No license file exists yet (see README §License). Contributions are
accepted only on the understanding that the license choice is pending;
do not submit code you cannot license compatibly.
