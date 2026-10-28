# Scoring rubric

Verdicts, one per report and known defect:

- `exact`: the report states the defect as a finding, at the same root-cause location and with the same security effect as the advisory.
- `partial_finding`: the report states a finding that names the location or the mechanism, but not the security effect.
- `partial_note`: the report names the defect only as a hardening note, a deferred unit, or a rejected candidate. It is not a stated finding.
- `missed`: none of the above. A report that checks the area and says "not vulnerable" is `missed`.

A known defect counts only if its presence check shows it at the audited commit. If it is not present, every report is `missed` for it, and the defect drops out of the score.

False finding: a stated finding that the check shows is documented behaviour, or does not occur. A low-severity real finding that is not a known defect is not false.

Score per report and run:

- Main score = exact × 1 + (partial_finding + partial_note) × 0.5 − false × 0.5.
- Strict score = exact × 1 + partial_finding × 0.5 − false × 0.5. A `partial_note` earns nothing.

Judge only what the report says. Do not give credit for what the tool might have found. A reproduction in the report is not required for a verdict, but the judge's own presence check decides whether a finding is real.
