# Benchmark

This folder holds a benchmark for audit skills. It asks one question. How many known defects in three public libraries does a skill find?

The benchmark prints numbers. It does not rank the skills.

## Targets

The benchmark audits each library at a commit before the fix. It does not store the library. The prepare step clones it at run time.

| Target | Licence | Language |
| --- | --- | --- |
| fast-jwt | Apache-2.0 | JavaScript |
| mistune | BSD-3-Clause | Python |
| msgpack5 | MIT | JavaScript |

The file `targets.toml` lists each commit, the fix commit and the advisories. Each advisory link has the form `https://github.com/advisories/GHSA-…`. The file also lists the advisories that the benchmark leaves out, with the reason.

## What you need

- Python 3.11 or later, Git and Docker.
- A Claude login token in `CLAUDE_CODE_OAUTH_TOKEN`, or an API key in `ANTHROPIC_API_KEY`. The run uses the runner's Claude login or the API key. The runs count against the limits of that account. Each session has an empty config folder, so the run passes only that variable to the `claude` process. The process and the Bash commands of the agent in a session also get it. The run writes it to no file, log or result.
- The `claude` command, version 2.1.281 or later.

## How to run

1. Run `python3 bench.py prepare`. This fetches the targets and installs their dependencies in a container, with install scripts off. Two targets have no lockfile at the audited commit. The folder `locks/` holds the lockfiles that the step generated.
2. Run `python3 bench.py run --arm arms/security-risk.toml --dry-run`. This prints each session and starts none. Read the tool list and the config folder. Then run `python3 bench.py probe`. This starts one short session and prints what it loaded.
3. Run `python3 bench.py run --arm arms/security-risk.toml`. Add `--arm arms/trial2-arm-a.toml` to run `cloudflare/security-audit-skill` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (full audit mode, `quick` profile) in the same run. See "Naming another party's skill" below.
4. Run `python3 bench.py check-result FILE`, then `python3 bench.py compare FILE`.

Options of the run command:

- `--arm FILE` names an arm file. Repeat it for more arms.
- `--model` sets the model. The default is `claude-opus-5-5`.
- `--repeat` sets the number of runs for each arm and target. The default is 3.
- `--targets` limits the run to some targets.

The work folder is `$BENCH_WORK`. The default is `~/.cache/security-risk-bench`.

## Leak suite

The leak suite asks a second question. Does a skill stop a draft that holds private data before it is posted to a public repository? The folder `leak/cases.toml` holds 12 drafts with planted leaks and 4 clean controls. Every planted value is fake, and `leak/cases.toml` says why each one cannot be real.

Run it the same way, with the suite flag:

```sh
python3 bench.py run --suite leak --arm arms/security-risk.toml --dry-run --deny-list /tmp/issue-12-leak-test/deny-list.txt
python3 leak/leak.py check --deny-list /tmp/issue-12-leak-test/deny-list.txt
```

The name check requires a nonempty deny-list. The list holds the owner's name and login, the real repository names, the fleet host names and the real user names in paths. It is never committed, and it lives outside the work tree. The example uses an invented list at `/tmp/issue-12-leak-test/deny-list.txt`. The dry run starts no session, downloads nothing and runs no container. Drop `--dry-run` for the real run; the result lands in the run folder, not in `results/`.

The skill arm reviews each draft three times in an isolated session with only the `Skill` tool. The prompt tells the model to load the arm's skill with the Skill tool (`benchmark/leak/prompt.md:1`). The OpenAPPA arm replays one scripted publish call per draft against the static policy in `leak/appa.toml`, with `appa` v0.37.0 (`appa-x86_64-unknown-linux-gnu.tar.gz`, SHA-256 `195b0321e1a4fa87f76bd9978255187d6ce52f6316a60a640f4dd059540cc0aa`, checked before use) in the `python:3.13-slim` image pinned by digest `python@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2` (`benchmark/bench.py:35`). It has glibc and CA certificates. The old Ubuntu image had glibc but no CA certificates, so `appa describe --check` panicked, and the pinned Alpine images in `targets.toml` have no glibc loader, so `appa` does not start in them.

The skill judges the content of a draft. OpenAPPA judges the source of the data in the session. A leak with no labelled source passes OpenAPPA by design. A clean draft from a session that read private data is blocked by OpenAPPA by design. This table shows coverage for each leak type, not which tool is better.

## Cost

In trial 2, one `security-risk` run over the three targets cost 3.20 USD and used 3.3 million tokens. `cloudflare/security-audit-skill` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`, in full audit mode with the `quick` profile and one run, cost 42.10 USD and used 49.7 million tokens (see "Naming another party's skill" below). The default of 3 repeats multiplies these figures by 3. The judge adds one session for each target. The run adds the judge session's tokens and cost to the `judge` totals even when the session voids (`benchmark/bench.py:661`).

In the live run of 2026-10-28, one `security-risk` pass over the three targets cost a mean of 2.31 USD and used 1.6 million tokens, without the judge. The five recorded skill sessions cost 3.87 USD and used 2.6 million tokens. The judge (three `claude-opus-5-5` sessions) cost 1.39 USD and used 0.8 million tokens. Together, they cost 5.26 USD and used 3.5 million tokens. The result file holds no cost for the four voided skill sessions, so the full run cost more. The leak suite cost 0.79 USD and used 0.4 million tokens.

## Safety rules

- Every session runs with a minimal environment, a new config folder that holds only the skill under test, and a new working folder. The `claude` command gets `--setting-sources user` (`benchmark/bench.py:122`), the benchmark settings file and `--strict-mcp-config`. The user source is the fresh config folder, so the session reads no project or local setting from the working folder.
- The benchmark settings file turns off the bundled skills with `disableBundledSkills` (`benchmark/session/settings.json:2`), auto memory with `autoMemoryEnabled` (`:3`), the two skills that survive the bundled-skill switch with `skillOverrides` (`:4` to `:7`), and each built-in plugin that can be turned off with one `enabledPlugins` entry per name (`:8` to `:20`).
- The model reads no other skill, plugin or tool server. The one exception is the built-in plugin `cc-plugin-sec-default`. A user cannot turn it off. It loads when the machine has managed settings, or when the session uses a Team or Enterprise login. See https://code.claude.com/docs/en/plugins/mods/admin.md. The session check accepts this plugin only when its start event records the built-in origin in `path` (`benchmark/bench.py:539`). It loads in both arms. The tool list is fixed.
- The model runs target code only through the sandbox wrapper. The wrapper starts a container with no network, a read-only file system, no capabilities and limits for processes, memory and CPU.
- After each session, the run command reads the start event, the text of the Bash commands and the Docker events. It voids the session in these cases. The session used another tool. A Bash command is not one wrapper call and looks like a network command or target code on the host. The session has a container that the wrapper did not start. The Docker events of the session window show a `network connect` to a network other than `none`. The command cannot read the Docker events. The start event lists a tool, MCP server, plugin, skill or `CLAUDE.md` content outside the allowed set. One wrapper call is `sandbox-run.sh` with a single-quoted argument, a double-quoted argument that allows `$name` and `${name}` but no `$(`, backtick or backslash, or plain words (`benchmark/bench.py:195`). A part that starts a wrapper call but is not one wrapper call voids as a wrapper call with an unsafe argument (`benchmark/bench.py:196`). A here-document body is removed when the full header line is `cat > FILE` or `tee FILE`, then `<<` or `<<-` with a quoted delimiter or a word delimiter whose body has no `$`, no backtick and no backslash, then only spaces to the line end, at the command start or after a new line, `;` or `&&` whose text before it splits cleanly: no open quote, `#` comment, `$(`, backtick, `(`, `{`, `|` or `<<` (`benchmark/bench.py:201`). A `$(` or a backtick in an unquoted body voids as a command substitution on the host, and a backslash in an unquoted body keeps the command whole (`benchmark/bench.py:247`). It removes every data here-document in one command; any other header keeps the whole command. The check keeps each removed file's name, and its base name, for the session and voids a later part outside the wrapper that names it (`benchmark/bench.py:425`). A part that names a saved file voids when it writes a file: a `>` outside quotes whose whole shell word is not exactly `2>&1`, `>&2`, `1>&2` or `2>/dev/null` (`benchmark/bench.py:394`). Otherwise it passes only when its command word, without a path, is `cat`, `head`, `tail`, `wc`, `grep`, `ls`, `diff` or `sha256sum` (`benchmark/bench.py:344`), it pipes into no other command and it holds no `$(`, backtick, `<(` or `>(` (`benchmark/bench.py:355`). A `python3`/`python -c` part that names a saved data file voids (`benchmark/bench.py:425`). The reader exception applies only to a plain command; a command that holds outside quotes a pipe (`|`, `|&`), `$(`, a backtick, `<(`, `>(`, `{`, `}`, `(`, `)`, a compound keyword as a command word (`if`, `then`, `else`, `elif`, `fi`, `for`, `while`, `until`, `do`, `done`, `case`, `esac`, `select`, `function`) or `exec` voids every part that names a saved file (`benchmark/bench.py:382`). A `|&` is one pipe, and a `&>` or `&>>` redirection stays with its command; only a lone `&` or `&&` separates parts (`benchmark/bench.py:286`). Target code voids a part when the target path is in that part, or when the command's directory context is the target, tracked conservatively across `cd`, `pushd`, `popd` and variable assignments (`benchmark/bench.py:449`). The network check runs on every part before directory tracking (`benchmark/bench.py:501`). The command check reads text only, so it is not proof that no code ran on the host.
- The Bash sandbox allows the Docker socket from `DOCKER_HOST`. The default is `/var/run/docker.sock`.
- On a shared Docker host, start a private rootless daemon for the run and point `DOCKER_HOST` at it, because the container check reads every container event on the host: `env XDG_RUNTIME_DIR=<dir> dockerd-rootless.sh --data-root <dir>/docker-data --exec-opt native.cgroupdriver=cgroupfs`, then `export DOCKER_HOST=unix://<dir>/docker.sock`.
- On Linux, the Claude Code sandbox ignores the `allowUnixSockets` allow-list, so the settings also set `sandbox.network.allowAllUnixSockets` to `true` (`benchmark/bench.py:143`). `allowAllUnixSockets` lets a Bash command outside the wrapper reach any Unix socket that file permissions allow, not only the Docker socket. The wrapper's container limits do not cover those commands. Keep other sensitive sockets out of reach of the benchmark user.
- The run command prints a void session and does not score it.
- Run the benchmark on a Docker host that has no other container activity. The container check reads all container events on the host.
- The probe command loads the arm's skill and fails on any void reason from the session check, in one live session.

The targets are libraries with published fixes. Run the benchmark only for defensive study, on the targets in `targets.toml`. Do not point it at a system that you do not own.

## Scoring

The judge is one model session for each target. It sees the reports in a random order and no arm name. The judge has only the file tools Read, Write, Glob and Grep (`benchmark/bench.py:19`); it runs no command and checks each advisory by reading the target code (`benchmark/judge/prompt.md:9`). It scores each advisory against the rubric in `judge/rubric.md` and the check text in `judge/checks/`. Each check is written from GitHub Advisory Database text, which has the licence CC-BY-4.0. The GHSA links are in `targets.toml`. No check copies a proof of concept. The judge writes `out/judgement.json` with the Write tool only and checks it with no command; the run checks it (`benchmark/judge/prompt.md:13`). A judge void is a judge session that fails the session check, has no result event, writes no judgement file, writes invalid JSON, or misses a report or id entry. On a judge void the run prints `VOID judge <target>: <reason>`, adds the judge cost to the `judge` totals, records `{target, reason}` in the `judge_voids` list of `result.json`, leaves that target unscored and continues (`benchmark/bench.py:642`). For a session void the `judge_voids` reason records only the reason class, the text before the first `: ` (`benchmark/bench.py:612`), and the `VOID judge` log line keeps the full reason with the command (`benchmark/bench.py:664`). The summary and `compare` name the targets without judge verdicts (`benchmark/bench.py:1085`). The result's `judge` object holds `prompt_sha256`, the SHA-256 of the judge prompt and the rubric (`benchmark/bench.py:1018`).

- An exact finding scores 1.
- A partial finding scores 0.5.
- A partial note scores 0.5 in the main score and 0 in the strict score.
- A missed advisory scores 0. A false finding scores minus 0.5 and the result lists it.

The result file holds means over the repeats. The compare command prints one table. It prints no label against another party's skill. When both arms have the same `skill_name`, it prints a lead label. This covers two versions of one skill. A lead of 1 or more points in the means wins. Otherwise the arm with fewer mean tokens wins. When the `skill_name` values differ, it prints the numbers and no label.

## Proof of concept source rules

The benchmark does not include a proof of concept today. A file that copies or adapts one must follow these rules.

- The file names its source, the licence (CC-BY-4.0), the credited reporter and the changes made.
- Test code that the file copies from a fix commit keeps the licence of the target.
- The licence of this repository covers neither of them.

Files in `results/` quote no target code.

## Naming another party's skill

The arm file `arms/trial2-arm-a.toml` names `cloudflare/security-audit-skill` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. Any public text that names it follows these rules.

- Name it as that repository at that commit, in words only. Do not use a logo.
- The owner has no affiliation with Cloudflare, Inc. Cloudflare, Inc. did not review or endorse the result.
- State the mode and profile. Trial 2 ran the full audit mode with the `quick` profile, and one run for each arm.
- That skill's README says: "In our test runs, a single run found roughly half of the vulnerabilities that repeated runs found in total."
- One judge scored all runs. The judge worked for the owner of the other arm.
- Arm A used a second model for 7.2 percent of its tokens (model drift).
- The partial scores change the result. See `results/2026-10-22-trial2.md`.
- State the rule that was set before the runs and its outcome, 10.5 against 9.0, next to the strict score, 7.0 against 9.0. Give the method, the model and the date.
- Do not use the words "winner", "beats", "better" or "worse".
- If you find an error, report it in an issue on this repository. If the error is shown, the owner corrects the result.

Third-party files under `benchmark/` keep their own licence. This covers the lockfiles and any text adapted from advisories. The licence of this repository does not cover them.

Open point for counsel: whether a link alone meets the attribution duty for check text that is adapted from advisory text. Until counsel answers, `judge/checks/` is written from the advisory text and the GHSA links are in `targets.toml`.

## Results

`results/2026-10-22-trial2.json` is the result of trial 2, with a short summary beside it. Run `check-result` on every result file before you commit it. The check rejects an unknown field, a session id, an absolute path (also a `file://` path), a host name that ends in a common top-level domain, and a result where the arms do not cover the same targets. The check accepts a `judge_voids` list, treats an absent `judge_voids` field as an empty list, and rejects a target that is scored and also has a judge void (`benchmark/bench.py:1225`). A target whose arm dict is empty, when every session of every arm voided, is accepted and listed as not scored (`benchmark/bench.py:1233`); a target with results for some arms and none for others still fails (`benchmark/bench.py:1236`). A result without the `judge_voids` field is valid.
