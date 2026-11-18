# security-risk-skill

Minimal security risk assessment guidance for agents.

## Why it exists

An agent that reviews security can start to test a system, or read its data, logs or credentials, before anyone has authorized it. This skill tells the agent to confirm the target, the authorization, the data handling and the permitted actions first. The skill is one short file of guidance, `SKILL.md`, so that an agent can read all of it each time.

## What it does

The skill helps an agent review a written design or spec for security risk. It also helps the agent assess a target that you have authorized, and verify fixes that you have approved.

Before any testing, the skill tells the agent to confirm the target, the authorization, the data handling and the permitted actions. Each finding names the threat, the impact, the affected asset and a focused mitigation.

## What it does not do

- It does not guard tool calls while an agent runs. It is guidance that the agent reads, not a runtime filter.
- Its rules tell the agent not to test a system that you have not authorized.
- It does not declare legal compliance. It does not replace incident command, system ownership or qualified review.

## Dependencies

| Dependency | Why you need it |
| --- | --- |
| Node.js 22.20.0 or later, with npm | `npx` runs the skills CLI, and the skills CLI 1.9.0 needs this Node.js version. |
| Git | The skills CLI uses Git to fetch the repository at the release tag. |

The skill itself has no dependencies. The benchmark has its own dependencies. They are in [benchmark/README.md](benchmark/README.md).

## Install

Install the latest version:

```sh
DO_NOT_TRACK=1 npx skills add https://github.com/asabirov/security-risk-skill --skill security-risk --agent claude-code codex --global
```

Update it later:

```sh
DO_NOT_TRACK=1 npx skills update security-risk --global
```

`DO_NOT_TRACK=1` turns off the telemetry of the skills CLI. The CLI needs Node.js, npm and Git.

## Use

Ask your agent for a review in plain words. Examples:

- "Review this design for security risk."
- "Assess the security risk of this spec before we build it."
- "Verify the fix for this finding on the staging host that I have authorized."

Before the agent tests a system, it confirms the target, the authorization, the data handling and the permitted actions.

## Version

The skill version lives in `metadata.version` in `SKILL.md`. The changes for each version are in `CHANGELOG.md`.

## Benchmark

The benchmark in [benchmark/README.md](benchmark/README.md) counts how many known security advisories an audit skill finds in three open-source libraries. It can run this skill and other skills on the same targets.

The [live run of 2026-10-28](benchmark/results/2026-10-28-live.md) ran this skill on `claude-opus-5-5`, with three repeats, on three targets that hold 20 advisories.

| Measure | Result |
| --- | --- |
| Score | 10.5 |
| Strict score | 10.5 |
| Mean cost of one pass over the three targets, without the judge | 2.31 USD |
| Mean tokens of one pass over the three targets, without the judge | 1,623,699 (about 1.6 million) |
| Void skill sessions | 4 of 9 |

An exact finding scores 1 and a partial finding scores 0.5. A partial note scores 0.5 in the score and 0 in the strict score. A false finding scores minus 0.5. The rules are in [Scoring](benchmark/README.md#scoring).

The result has these limits:

- Only this skill ran. The [trial 2 summary](benchmark/results/2026-10-22-trial2.md) holds the comparison with another skill.
- The means cover only the sessions that passed. They use two runs for `fast-jwt` and `mistune` and one run for `msgpack5`, not three, because of the four void sessions.
- The result file holds no cost for the four void sessions, so the full run cost more.
- The run used a private rootless Docker daemon on the shared host, with no other container activity.

## Licence

MIT. See `LICENSE`.
