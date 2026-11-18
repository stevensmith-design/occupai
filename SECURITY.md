# Security policy

OccupAI is a side project, maintained on a best-effort basis. It's a set of read-only agent automations, not a security product, so please don't rely on it as your only safeguard.

## Reporting a problem with the kit itself
Please report privately, not in a public issue, if you find a way the kit could:
- read, print or store a secret value,
- write to, modify or run code in a scanned project,
- be steered by content on a fetched web page (prompt injection) into doing something outside its prompts,
- or otherwise break the safety rules in `prompts/howto.md`.

Use GitHub's private vulnerability reporting ("Report a vulnerability" on the Security tab). I'll reply as soon as I can, usually within a week, and credit you in the changelog if you'd like.

Missed detections (a check that should have caught something) and false positives are welcome as normal issues. Please use fake values in your examples, never real secrets.

## Supported versions
Only the latest release.
