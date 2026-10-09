# ATT&CK coverage

<!-- Generated from rule metadata by tools/coverage.py. Do not edit by hand. -->

Enterprise ATT&CK techniques referenced by rules in this repository. Technique names
come from ATT&CK v19.2 (`data/attack-enterprise-techniques.csv`).
Tactic names follow the current ATT&CK vocabulary (including `stealth` and
`defense-impairment`).

| Technique | Name | YARA rules | Sigma rules |
| --- | --- | --- | --- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | `LSASS_Memory_Dump_Command` | `proc_access_win_lsass_memory_read_access` |
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Command Obfuscation | `PowerShell_Encoded_Command_Launcher` | `proc_creation_win_powershell_encoded_command` |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | - | `proc_creation_win_schtasks_create_suspicious_action` |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | `PowerShell_Download_Cradle`, `PowerShell_Encoded_Command_Launcher` | `proc_creation_win_powershell_encoded_command` |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `Certutil_Download_Or_Decode_Command`, `PowerShell_Download_Cradle` | `proc_creation_win_certutil_url_download` |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | `Certutil_Download_Or_Decode_Command` | - |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | `Shadow_Copy_Deletion_Command` | `proc_creation_win_shadow_copy_deletion` |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | `WebShell_ASPX_Process_Start_Request_Input`, `WebShell_PHP_Eval_Request_Input` | `proc_creation_win_webserver_spawns_shell` |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | `Registry_Run_Key_Persistence_Command` | `registry_set_win_run_key_suspicious_target` |
| [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Clear Windows Event Logs | - | `proc_creation_win_wevtutil_clear_log` |

| Kind | Rules | Distinct techniques |
| --- | --- | --- |
| YARA | 8 | 8 |
| Sigma | 8 | 9 |
| Combined | 16 | 10 |
