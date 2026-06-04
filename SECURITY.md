# Security Policy

ScopeForge is intended for authorized security research, internal assessment,
and lab validation. Do not use it against assets you do not own or have written
permission to test.

## Built-in Guardrails

- Active probing is refused unless the target is explicitly inside the loaded
  scope file.
- Scope files include an expiration timestamp.
- Active actions are written to a hash-chained JSONL evidence ledger.
- The project does not include stealth, persistence, credential theft, exploit
  delivery, or lateral movement features.

## Reporting Issues

Please open a private security advisory or contact the maintainers before
publicly disclosing a vulnerability in this project.
