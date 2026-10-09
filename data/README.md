# Reference data

| File | Content | Upstream |
| --- | --- | --- |
| `ATTACK_VERSION` | Enterprise ATT&CK version string | [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) |
| `attack-enterprise-techniques.csv` | Technique ID, name and tactics for non-revoked, non-deprecated Enterprise techniques | Same, collection version in `ATTACK_VERSION` |
| `attack-enterprise-tactics.csv` | Tactic ID, shortname and display name | Same |

Tactic shortnames follow the current ATT&CK vocabulary. As of Enterprise ATT&CK 19.x the
former `defense-evasion` tactic is published as `stealth` (`TA0005`) and a separate
`defense-impairment` tactic (`TA0112`) exists. Sigma `attack.<tactic>` tags in this repository
use those current shortnames.

To refresh after a new ATT&CK release, regenerate the CSV files from the corresponding
`enterprise-attack-<version>.json` STIX bundle and update `ATTACK_VERSION`.
