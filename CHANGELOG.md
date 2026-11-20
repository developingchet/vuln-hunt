# Changelog

## 0.1.0 - unreleased

Reliability and evidence-integrity release.

- The attestation no longer passes through the session's model. `vuln-hunt-attest.js --emit-run` writes a private
  run directory outside the repository holding the attestation and a generated workflow script with the
  attestation embedded byte-for-byte, and `/vuln-hunt:scan` starts the workflow from that script's path. Array
  order and large range evidence survive transit unchanged, and because the script parses the embedded JSON text
  rather than evaluating an object literal, a top-level directory named `__proto__` survives too. The script
  leaves the runtime's `args` untouched and refuses an `args.attestation` that differs from its embedded copy;
  a run interrupted part-way can be resumed with the same script path. Passing the attestation as workflow
  arguments to the plain template still works.
- `maxConcurrentAgents` (1-256) caps every agent this one run dispatches, including verification panels fanned
  out inside `pipeline()` and `parallel()` tasks and every retry. Admission is FIFO and a failed agent releases
  its slot. A rate-limit-classified failure gets one immediate retry; the native runtime ceiling still applies
  above the configured one.
- No candidate is silently dropped: every candidate's ledger entry ends in `VERIFIED`, `REJECTED`,
  `PREDATES_CHANGE`, `UNRESOLVED_EVIDENCE`, `UNRESOLVED_INFRASTRUCTURE` or `NOT_REACHED`. A missing
  verification vote is retried immediately, then once more in a recovery pass that retries only the missing
  seats, preserving all completed votes; a panel that still cannot complete is reported as unresolved by
  infrastructure with its missing seats named, never as a clean verdict.
- Citations are validated mechanically. The helper's new `--validate-citations` checks every researcher receipt,
  verifier citation and adjudicator citation against the live manifest and real line counts, so a nonexistent
  file, a prefix-matched directory, an impossible line number, or a path through a symlink or junction cannot
  support a verdict or a coverage receipt. Validation fails closed: a citation the helper did not confirm,
  including every citation in a batch whose output did not come back intact, is dropped exactly like an invalid
  one, and a finding that loses its verdict that way is unresolved by infrastructure rather than by evidence.
  The helper echoes a hash of its input and adds a `resultHash` over its output, which detects a garbled or
  truncated transport in either direction, not a mechanic that rewrote the output on purpose. Input reaches the
  helper base64-encoded in batches bounded by size, and its output names citations by index, so no file name
  text appears in the command the mechanic runs or in what it copies back. Coverage gains a `receipt-thin`
  state (a 200-file unit needs more than one distinct citation; salvage revisits thin units at or above
  `salvageRisk`) and a `citationsValidated` status.
- `policyDocs` makes repository security-policy documents first-class: attested with `--policy-doc`, hashed into
  the state hash, and read by every researcher and verifier as untrusted evidence. A contradicted claim is
  evidence for a finding; a vulnerability the documents never mention is still reported; out-of-scope lists are
  disclosure-program metadata, not a filter. Attestation version 5 adds `policyDocs`; a version 4 attestation is
  refused, since the freshness check and the new validation modes need the helper that writes version 5.
- Dynamic scanning is configurable without editing workflow scripts: a typed `reproEnvironment` descriptor
  (backend, image, locations, runtimes, entrypoints, instructions, limits, timeout) reaches the reproduction
  agent as structured data, `reproMinSeverity` selects which verified findings to reproduce, and reproduction
  statuses distinguish `REPRODUCED` from `NOT_REPRODUCED`, blocked, timeout and infrastructure failures. A finding
  is `EXECUTION_REPRODUCED` only when the reproduction also affirms the vulnerable path was reached with
  attacker-controlled input. A generic passing test suite is environment readiness, never a reproduction; a
  failed reproduction never refutes a statically verified finding.
- Cross-run identity: each verified finding carries a deterministic `findingId` that leaves out the line number,
  and the helper's `--prior-findings` relates this run's findings to the most recent earlier runs'
  `findings.jsonl` as `REPRODUCED_AGAIN`, `TENTATIVE_MATCH` or `NEW`. A prior finding that matches a candidate
  this run did not verify is `REASSESSED_NOT_VERIFIED`, and every other one stays `NOT_REASSESSED`; neither is
  treated as fixed. Candidate IDs are per-run values and are never compared across runs alone.
- The written report is validated: `--validate-report` checks the report files exist and parse, that every
  verified finding appears once with this run's `findingId`, `relation` and evidence level and with the file,
  line and symbol the next run needs, and that every unit carries its ledger status, with an echoed expectation
  hash. A closing freshness check, taken before the report so the report can state it, flags a tree that changed
  during the run as `sourceChangedDuringRun`.
- The workflow returns a compact summary — identities, counts by status, coverage and reconciliation summaries,
  report-validation verdict — instead of duplicating the full report contents in the conversation. When the
  report was not written, failed, or did not pass validation, the full result is returned as `structuredResult`.
- `runId` values of `.` and `..`, names ending in a dot and Windows device names are refused in the workflow
  and the helper, closing a reserved-path escape and Windows path aliasing.
- Policy documents are read through the same checked descriptor as citations, refusing a symlink or junction on
  every platform, and an attested document the run does not name in `policyDocs` is reported as inactive.
- The attestation reads `.vuln-hunt/.gitignore` and Git's `objects/info/alternates` through the descriptor it
  checked, so the file can no longer be swapped for a symlink between the check and the read.

## 0.0.1 - 2026-11-15

First release as a Claude Code plugin.

- Installs from the `developingchet/vuln-hunt` marketplace with `/plugin install vuln-hunt@vuln-hunt`, adding the
  `/vuln-hunt:vuln-hunt` workflow, the three worker agents, and the `/vuln-hunt:scan` and `/vuln-hunt:helpers`
  skills. `Install-VulnHunt.ps1` remains for installs without the plugin system.
- `/vuln-hunt:scan` attests the repository with the bundled helper and runs the workflow with strict provenance,
  for the whole tree or a Git range.
- The workflow prefers the plugin's workers, which a scanned repository cannot replace, and falls back to the
  bare worker names that the manual install and the launcher define.
- Workflow options are validated: options passed as a JSON string are parsed, and unknown keys, wrong types and
  out-of-range values are refused instead of replaced by defaults.
- The attestation treats assume-unchanged and skip-worktree entries as a dirty tree, refuses untracked nested Git
  repositories, rejects malformed ranges such as `A..B..C`, ignores the user's rename settings when listing a
  change, and accepts a working directory that differs from Git's root only in letter case or 8.3 form.
- The freshness check also confirms the helper and Node paths that ran, and its command works from Bash or
  PowerShell with quoted paths.
- A project agent that shadows a worker is refused however its frontmatter is written, including through linked
  directories.
- A missing worker inside a parallel stage stops the run with its name, and a report that cannot be written no
  longer discards the scan's result.
- PREDATES_CHANGE verdicts count only in change reviews, and the adjudicator sees the same change evidence as the
  panel.
- Released as a zip with a checksum file, both signed with cosign.
