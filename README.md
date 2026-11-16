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

Run this command. It installs release v0.2.2, the newest release, for Claude Code and Codex:

```sh
DO_NOT_TRACK=1 npx skills add https://github.com/asabirov/security-risk-skill/tree/v0.2.2 --skill security-risk --agent claude-code codex --global
```

`DO_NOT_TRACK=1` turns off the telemetry of the skills CLI. To update, take the newest tag from the releases page of the repository, and run the command again with that tag. To go back, run it again with the older tag.

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

## Licence

MIT. See `LICENSE`.
