# Architecture

How secure-unzip is meant to be built: package boundaries, the order in which an archive entry is
validated and written, and the attacks each check exists to stop.

No code exists yet (2026-08-06) — these docs describe the target design from `CLAUDE.md` and must
be re-verified once packages land.

* [Module Layout](module-layout.md) - the four Go packages and what each owns
* [Extraction Pipeline](extraction-pipeline.md) - per-entry validation and write order
* [Threat Model](threat-model.md) - the attacks in scope and the control that stops each
