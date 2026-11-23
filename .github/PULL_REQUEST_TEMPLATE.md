## Change

<!-- What changes and why. Link the issue it resolves, for example "Fixes #123". -->

## Checks run

<!-- Tick what you ran and passed. Leave a box unticked and say why if you skipped it. -->

- [ ] `node tests/run.js` (on Windows, Linux or both; say which)
- [ ] `claude plugin validate --strict .`
- [ ] `SHA256SUMS.txt` regenerated for every changed, added or removed file outside `.github/`
- [ ] For option changes: `vuln-hunt-options.js` and the validator in `vuln-hunt.js` both updated, and the README tables regenerated with `--table` and `--presets-table`
- [ ] New behaviour has a test in `tests/run.js` or `tests/options.js`
- [ ] User-visible changes have a `CHANGELOG.md` line and the docs they affect are updated; docs-only changes are exempt

Manual checks, such as a scan run with `--plugin-dir`, and anything not tested:

## Compatibility

<!-- Does this change the attestation format, an option's name or default, a report file or a release artifact?
Say how an existing install or an older run is affected, and how to roll back. Write "none" if it does not. -->

## Security model

- [ ] No worker gains a tool, the researcher stays Read, Glob and Grep, and no worker stage falls back to the default agent; or the change explains why it is safe.
- [ ] No check moves from code into a prompt, and repository text is still treated as untrusted evidence.
- [ ] Any change to the attestation format, the option schema or the report files is described above and has a `CHANGELOG.md` line.
- [ ] Tests and examples use throwaway repositories, and no attestation, result or report from a real repository is committed.
