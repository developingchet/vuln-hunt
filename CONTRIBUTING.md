# Contributing to vuln-hunt

Bug reports, documentation fixes and pull requests are welcome. For a larger change, such as a new stage, option
or worker, open a feature request first so the design can be agreed before you write it.

**Security problems in vuln-hunt are not reported in issues or pull requests.** Follow [SECURITY.md](SECURITY.md).
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), and [SUPPORT.md](SUPPORT.md) says where
each kind of question belongs.

## Reporting a problem

Use the [issue forms](https://github.com/developingchet/vuln-hunt/issues/new/choose). A bug report needs the
vuln-hunt version or commit, the Claude Code version, the operating system, how you installed and started it, and
the options you passed.

Scan output describes the repository that was scanned: file paths, code excerpts and, in a report, its
vulnerabilities. Before pasting attestations, results or reports, remove anything from a repository you may not
share, and never post an unfixed vulnerability in someone else's code. A problem reproduced on a small public or
throwaway repository is the easiest to act on.

False positives and missed vulnerabilities are worth reporting when the workflow's own rules let them through, for
example a finding verified without the citations it needs or a unit marked reviewed without receipts. The model
misjudging a single candidate is a known limit, described under
[Limits and cost](README.md#limits-and-cost).

## Development setup

You need Node.js (CI uses 22) and Git. Claude Code is needed only to validate the plugin and to run a real scan.

```bash
git clone https://github.com/developingchet/vuln-hunt.git
cd vuln-hunt
node tests/run.js
claude plugin validate --strict .
```

The suite builds throwaway Git repositories in the system temp directory and needs no network access. On Windows,
if `TEMP` is an 8.3 short path, set `TEMP` and `TMP` to a long path first. The installer tests run only on
Windows.

To try a change in Claude Code, load the plugin from your clone for one session with
`claude --plugin-dir /path/to/vuln-hunt`
([develop without a marketplace](https://code.claude.com/docs/en/plugins/create#develop-without-a-marketplace)), then run
`/vuln-hunt:scan` in a repository you are authorized to test. Run `/reload-plugins` after editing a file.

## Making a change

- Keep `vuln-hunt-attest.js`, `vuln-hunt-launch.js` and `vuln-hunt-options.js` free of dependencies, and working
  on Windows and Linux.
- An option change goes in both `vuln-hunt-options.js` and the validator in `vuln-hunt.js`; refresh the README
  tables with `node vuln-hunt-options.js --table` and `node vuln-hunt-options.js --presets-table`.
- Keep `agents/*.md` and `vuln-hunt-agents.json` in step. A change to a worker's tools needs a reason in the pull
  request; the researcher stays read-only (Read, Glob, Grep).
- Add a test to `tests/run.js` or `tests/options.js` for every behaviour change, and a line to `CHANGELOG.md` for
  every user-visible one; docs and community-file-only changes are exempt.
- Regenerate `SHA256SUMS.txt` from the repository root after changing, adding or removing a file outside
  `.github/`:

  ```bash
  git ls-files | grep -v -e '^SHA256SUMS\.txt$' -e '^\.github/' | LC_ALL=C sort | sed 's|^|./|' | xargs sha256sum -t > SHA256SUMS.txt
  ```

  This uses GNU `sha256sum` (Ubuntu, WSL or Git Bash on Windows). Stage or commit a new file first so
  `git ls-files` lists it, and `git rm` a removed file so it no longer does. `.gitattributes` keeps every
  checkout LF, so the hashes match CI's. `node tests/run.js` fails until the list matches.

## Pull requests

- Branch from `main` and keep each pull request to one change.
- Write the title as a [Conventional Commit](https://www.conventionalcommits.org/) subject, such as
  `fix: refuse a range with an empty endpoint` or `docs: explain policy documents`. Pull requests are squash-merged, so
  the title becomes the commit subject.
- Fill in the pull request template, including the checks you skipped.
- A pull request needs one approving review from a maintainer before it merges.
- CI runs the suite on Windows and Ubuntu and validates the plugin. CodeQL default setup also runs on the
  repository. The two test jobs must pass and the branch must be up to date with `main` before it can merge.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
