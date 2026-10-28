# security-risk-skill

An agent skill for security risk assessment and written design review.

## What it does

The skill helps an agent review a written design or spec for security risk. It also helps the agent assess a target that you have authorized, and verify fixes that you have approved.

Before any testing, the skill tells the agent to confirm the target, the authorization, the data handling and the permitted actions. Each finding names the threat, the impact, the affected asset and a focused mitigation.

## What it does not do

- It does not guard tool calls while an agent runs. It is guidance that the agent reads, not a runtime filter.
- Its rules tell the agent not to test a system that you have not authorized.
- It does not declare legal compliance. It does not replace incident command, system ownership or qualified review.

## Install

You need Node.js, npm and Git. Run this command:

```sh
DO_NOT_TRACK=1 npx skills add https://github.com/asabirov/security-risk-skill/tree/vX.Y.Z --skill security-risk --agent claude-code codex --global
```

Replace `vX.Y.Z` with the release tag that you want, for example the newest tag on the releases page of the repository. `DO_NOT_TRACK=1` turns off the telemetry of the skills CLI. To update, run the command again with the newer tag. To go back, run it again with the older tag.

Then ask your agent, for example: "Review this design for security risk."

## Version

The skill version lives in `metadata.version` in `SKILL.md`. The changes for each version are in `CHANGELOG.md`.

## Benchmark

The benchmark in [benchmark/README.md](benchmark/README.md) counts how many known security advisories an audit skill finds in three open-source libraries. It can run this skill and other skills on the same targets.

## Licence

MIT. See `LICENSE`.
