# Changelog

## 0.2.2 — 2026-10-28

### Changed

- **Judge void is a result, not a failure.** The judge writes `out/judgement.json` with the Write tool only and checks it with no command (`benchmark/judge/prompt.md:13`). A judge void records `{target, reason}` in `judge_voids`, adds the judge cost to the totals and leaves that target unscored instead of exiting (`benchmark/bench.py:642`); a session void records only the reason class, the text before the first `: `, and the `VOID judge` log line keeps the full reason (`benchmark/bench.py:612`, `benchmark/bench.py:664`). `check-result` accepts `judge_voids`, and `compare` names the targets without judge verdicts (`benchmark/bench.py:1085`). The `judge` object records `prompt_sha256` (`benchmark/bench.py:1018`).

- **The judge runs with file tools only and a fully voided target is not scored.** The judge session gets the tools `Read,Write,Glob,Grep` (`benchmark/bench.py:19`) and the judge prompt tells it to run no command and to decide each presence check by reading the target code with Read, Glob and Grep (`benchmark/judge/prompt.md:9`). `check-result` accepts a target whose arm dict is empty, when every session of every arm voided, and prints `<target>: not scored, every session voided` (`benchmark/bench.py:1233`); a target with results for some arms and none for others still fails (`benchmark/bench.py:1236`).

- **Isolated benchmark sessions.** The benchmark turns off the bundled skills, auto memory and the built-in plugins a user can turn off, and reads only the user setting source, so each session loads only the skill under test and the one unremovable plugin `cc-plugin-sec-default`. On Linux it allows every Unix socket, because the Linux sandbox ignores the socket allow-list (`benchmark/bench.py:143`). A wrapper call takes a single-quoted argument, a double-quoted argument that allows `$name` and `${name}` but no `$(`, backtick or backslash, or plain words (`benchmark/bench.py:195`); a part that starts a wrapper call but is not one wrapper call voids as a wrapper call with an unsafe argument (`benchmark/bench.py:196`). The command check removes a here-document body when the full header line is `cat > FILE` or `tee FILE`, then `<<` or `<<-` with a quoted delimiter or a word delimiter whose body has no `$`, no backtick and no backslash, then only spaces to the line end, at the command start or after a new line, `;` or `&&` whose text before it splits cleanly: no open quote, `#` comment, `$(`, backtick, `(`, `{`, `|` or `<<` (`benchmark/bench.py:201`). A `$(` or a backtick in an unquoted body voids as a command substitution on the host, and a backslash in an unquoted body keeps the command whole (`benchmark/bench.py:247`). It removes every data here-document in one command. It keeps each removed file's name, and its base name, for the session and voids a later part outside the wrapper that names it (`benchmark/bench.py:425`); a part that names a saved file voids when it writes a file: a `>` outside quotes whose whole shell word is not exactly `2>&1`, `>&2`, `1>&2` or `2>/dev/null` (`benchmark/bench.py:394`). Otherwise it passes only when its command word, without a path, is `cat`, `head`, `tail`, `wc`, `grep`, `ls`, `diff` or `sha256sum` (`benchmark/bench.py:344`), it pipes into no other command and it holds no `$(`, backtick, `<(` or `>(` (`benchmark/bench.py:355`). A `python3`/`python -c` part that names a saved data file voids (`benchmark/bench.py:425`). The reader exception applies only to a plain command; a command that holds outside quotes a pipe (`|`, `|&`), `$(`, a backtick, `<(`, `>(`, `{`, `}`, `(`, `)`, a compound keyword as a command word (`if`, `then`, `else`, `elif`, `fi`, `for`, `while`, `until`, `do`, `done`, `case`, `esac`, `select`, `function`) or `exec` voids every part that names a saved file (`benchmark/bench.py:382`). A `|&` is one pipe, and a `&>` or `&>>` redirection stays with its command; only a lone `&` or `&&` separates parts (`benchmark/bench.py:286`). It checks every part for a network command before directory tracking (`benchmark/bench.py:501`), and it tracks the target directory context across `cd`, `pushd`, `popd` and variable assignments (`benchmark/bench.py:449`). The probe loads the arm's skill and fails on any void reason, on a wrapper command that failed, or on a wrapper that started no container.

- **Leak image.** The OpenAPPA arm runs in `python:3.13-slim` pinned by digest, which has glibc and CA certificates, so `appa describe --check` no longer panics on a missing CA store.

- **Leak prompt names the skill.** The leak prompt's first line tells the model to load the arm's skill with the Skill tool, and the offline session check fails when the rendered prompt does not name it.

### Added

- **Repeatable benchmark.** You can run the same audit test on three public libraries again and read the scores of one or more skills side by side.

- **Licence and install guide.** You can use the skill under the MIT licence, and the README shows how to install it.

- **Leak test suite.** You can run 12 drafts with planted leaks and 4 clean controls through the skill and through an OpenAPPA policy.

- **Live benchmark runs.** The 2026-10-28 live audit scored `security-risk` 10.5, and the leak suite caught all 12 planted leaks; the results and the measured cost, judge included, are in `benchmark/results/`.

## 0.2.1 — 2026-10-24

### Changed

- **Written design review.** The skill reviews a written design or spec without an authorized target. Any testing, and checks of a running system, its data, logs or credentials, still require the target, authorization, data handling and permitted actions.

- **Quoted review data.** Before quoting live credentials, personal data or system output from text under review, the skill confirms data handling.

## 0.1.0 — 2026-09-29

Security-risk assesses security risk and verifies approved fixes, for anyone running an authorized security review.

### Added

- **Scope confirmation.** Before testing, the skill confirms the target, authorization, data handling and permitted actions. This keeps testing inside what was actually authorized.

- **Exposure versus misuse.** The skill separates exposed attack surface from proven misuse, so a real weakness is flagged without being called a confirmed incident, and the absence of observed misuse is not taken as proof of safety.

- **Structured findings.** You get each finding identified by threat, impact, affected asset and a focused mitigation, with verification chosen to fit the application or system. This keeps findings specific and actionable.

- **Verified versus planned containment.** The skill separates containment actually verified in the authorized environment from containment that is only planned, and records what remains untested. This prevents claiming a fix that was never checked.

- **Scoped authority.** A role name alone grants no active scanning, exploit verification, credential change or production containment authority, and sensitive evidence stays in its approved store. This keeps assessment work from becoming unauthorized action.
