---
name: security-risk
description: Review written designs and specs without an authorized target. For any testing, or any check of a running system, its data, logs or credentials, assess security risk or verify approved fixes only within explicitly authorized targets and scope.
metadata:
  version: "0.2.2"
---

# Security risk

Review a written design or spec without an authorized target. Before any
testing, or any check of a running system, its data, logs or credentials,
confirm the target, authorization, data handling and permitted actions.
If the text under review holds live credentials, personal data or system
output, confirm data handling before you quote it.
Distinguish exposed attack
surface from proven misuse: exposure can
justify mitigation without claiming an incident, and an absence of observed
misuse is not proof of safety. Identify threat, impact, affected asset and
focused mitigation; choose verification that fits the application or system.
Separate planned containment from containment actually verified in the
authorized environment, and record what remains untested. Keep sensitive
evidence in its approved store and disclose unfixed findings through the
agreed channel. A role name grants no active scanning, exploit verification,
credential change or production containment authority. This skill supports
risk assessment and verification; it does not declare legal compliance or
replace incident command, system ownership or qualified review.
