rule Shadow_Copy_Deletion_Command
{
    meta:
        id = "17222162-3827-4ebe-b6f7-b7b118cf91dd"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "Script content that deletes Volume Shadow Copies or the backup catalog, or disables Windows recovery, to inhibit system recovery"
        reference = "https://attack.mitre.org/techniques/T1490/"
        reference2 = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows"
        mitre_attack = "T1490"
        severity = "high"
        false_positives = "Backup administration scripts; deletion of all shadow copies outside a maintenance window should be confirmed with the system owner"
        license = "DRL 1.1"

    strings:
        $vssadmin = /\bvssadmin(\.exe)?\s+delete\s+shadows\b/ ascii wide nocase
        $wmic = /\bwmic(\.exe)?\s+shadowcopy\s+delete\b/ ascii wide nocase
        $wmi_ps = /Win32_ShadowCopy[^\r\n]{0,120}(\.Delete\(\)|Remove-WmiObject|Remove-CimInstance)/ ascii wide nocase
        $bcdedit = /\bbcdedit(\.exe)?\s+\/set\s+\{?\w+\}?\s+recoveryenabled\s+no\b/ ascii wide nocase
        $wbadmin = /\bwbadmin(\.exe)?\s+delete\s+catalog\b/ ascii wide nocase

    condition:
        filesize < 2MB
        and any of them
}
