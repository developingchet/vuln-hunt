# AGENTS.md

## Project

vuln-hunt is a Claude Code plugin: a dynamic workflow (`vuln-hunt.js`) that splits a Git repository into work units, sends read-only research agents through each one and reports only findings that independent verifiers confirm with citations. Everything is plain JavaScript on Node's standard library, with PowerShell wrappers for Windows; there are no runtime dependencies and no build step. The README's "How it works", "Architecture" and "Security model" sections describe the stages, the files and the trust boundaries.

| Path | Contents |
|---|---|
| `vuln-hunt.js` | The workflow: option and attestation validation, every stage, the verification rules and the result. It runs in Claude Code's workflow runtime, which cannot read files. |
| `vuln-hunt-attest.js` | Attestation helper: Git file list, work units, freshness fingerprint, postflight comparison, citation, report and prior-finding validation, `--emit-run` and `--self-test`. |
| `vuln-hunt-options.js` | Option schema, presets and the `/vuln-hunt:scan` argument parser; prints the README's options and presets tables. |
| `vuln-hunt-launch.js` | Starts Claude Code with session-level workers, user settings only and no MCP servers. |
| `agents/*.md`, `vuln-hunt-agents.json` | The three worker agents, as plugin agents and as the JSON the launcher and `Install-VulnHunt.ps1` use. |
| `skills/{scan,options,helpers}/SKILL.md` | The plugin's skills. |
| `*.ps1` | Windows wrappers: manual installer, prerequisite check, attestation and postflight. |
| `tests/run.js`, `tests/options.js` | The regression suite. |
| `.claude-plugin/` | Plugin manifest, marketplace entry and icon. |

## Setup and checks

Node.js (CI uses 22) and Git. The tests build throwaway Git repositories in the system temp directory and need no network access or Claude account; the installer tests run only on Windows.

```bash
node tests/run.js                 # full suite; CI runs it on Windows and Ubuntu
claude plugin validate --strict . # CI pins the Claude Code version in .github/ci/package.json
```

The suite runs the helper's `--self-test` in a throwaway repository automatically. To run that check by hand,
start from an empty scratch Git repository outside the clone and pass the absolute path to the helper; it
refuses to run from inside the repository that holds it.

On Windows, if `TEMP` is an 8.3 short path (`C:\Users\RUNNER~1\...`), point `TEMP` and `TMP` at a long path
so the suite can derive a distinct short name and exercise the helper's acceptance of both forms. CI does the
same in `.github/workflows/test.yml`.

## Conventions

- Keep the helper, launcher and options script dependency-free (Node built-ins only), and keep them working on Windows and Linux from Bash or PowerShell.
- `vuln-hunt.js` keeps its own option validator because a workflow script cannot read files. A change to an option goes in both `vuln-hunt-options.js` and `vuln-hunt.js`; `tests/options.js` checks that they accept and refuse the same values. Regenerate the README tables with `node vuln-hunt-options.js --table` and `--presets-table`.
- `agents/*.md` and `vuln-hunt-agents.json` describe the same workers and must stay in step; the tests compare them. The researcher's tools stay exactly `Read, Glob, Grep`, and every worker keeps `omitClaudeMd: true`.
- `SHA256SUMS.txt` lists every tracked file except itself and `.github/`, hashed as the LF bytes `.gitattributes` checks out. After changing, adding or removing such a file, regenerate it from the repository root (`-t` keeps Git Bash's output identical to Linux's):

  ```bash
  git ls-files | grep -v -e '^SHA256SUMS\.txt$' -e '^\.github/' | LC_ALL=C sort | sed 's|^|./|' | xargs sha256sum -t > SHA256SUMS.txt
  ```

  This uses GNU `sha256sum` (Ubuntu, WSL or Git Bash on Windows). A new file must be staged or committed before
  `git ls-files` lists it, and a removed file needs `git rm` so it no longer does. Run `node tests/run.js`
  afterwards; its release checksum test fails until the list matches.
- `skills/*/SKILL.md` carry Claude Code extensions alongside the Agent Skills fields: helpers and scan set
  `disable-model-invocation`, scan sets `argument-hint`, and scan and options use the list form of
  `allowed-tools` (those patterns contain spaces). Keep them; they carry the scan's command guards. The Agent
  Skills reference validator, `skills-ref validate`, accepts `options` and the list form of `allowed-tools`,
  and rejects `helpers` and `scan` only for those vendor fields, so those two failures are expected.
- Add a test to `tests/run.js` or `tests/options.js` for every behaviour change. User-visible changes get a
  line under the heading for the next version in `CHANGELOG.md` (`## <version> - <date>`), adding that
  heading if absent; docs and community-file-only changes are exempt. Releases raise `version` in
  `.claude-plugin/plugin.json`, and the release workflow refuses a tag that does not match it or a version
  with no changelog entry.
- Commit subjects follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`); pull requests are squash-merged.

## Security boundaries

- Every model call in the workflow goes through a worker with a fixed tool list, and the workflow checks schemas, citations, votes and hashes in code. Do not move a check from code into a prompt, give a research stage a tool beyond Read, Glob and Grep, or let a worker stage fall back to the default agent (only dynamic reproduction uses it, because it must run code).
- Repository text is untrusted evidence in every prompt. Keep that framing, and keep the helper's safeguards:
  it records a dirty tree (and refuses one for a range or strict provenance), flags index flags, nested
  repositories and linked paths, strips Git environment variables, resolves `git` from outside the scanned
  repository, refuses to run when the helper or the Node runtime sits inside it, and rejects project agents
  that shadow a worker.
- Tests create their own repositories; never point the suite or a scan at code you are not authorized to test, and never commit `.vuln-hunt/` run output, attestations or reports from a real repository.
- Dynamic mode runs target code. Its `containment` field is the operator's assertion; see `ISOLATION.md` before changing anything that reaches execution.
- Vulnerabilities in vuln-hunt itself are reported privately as `SECURITY.md` describes, not in issues or pull requests.

## Pull requests

Fill in `.github/PULL_REQUEST_TEMPLATE.md`: list the checks run and those skipped, and say whether the change touches a worker's tools, the attestation format, the option schema or the checksum list.
