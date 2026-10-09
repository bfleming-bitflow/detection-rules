rule Registry_Run_Key_Persistence_Command
{
    meta:
        id = "1f23184b-2091-478d-ad93-c6d4348e5dd6"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "Script content that adds a Run or RunOnce registry value pointing to a user-writable staging directory or a script interpreter"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
        reference2 = "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys"
        mitre_attack = "T1547.001"
        severity = "medium"
        false_positives = "Endpoint configuration scripts that register login helpers; review the value data"
        license = "DRL 1.1"

    strings:
        $reg_add = /\breg(\.exe)?\s+add\s+["']?(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?["']?\s/ ascii wide nocase
        $ps_set = /(New-ItemProperty|Set-ItemProperty)\s+[^\r\n]{0,40}(HKCU|HKLM):\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?\b/ ascii wide nocase

        $target_temp = /\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public)\\/ ascii wide nocase
        $target_env = /%(TEMP|TMP|PUBLIC)%/ ascii wide nocase
        $target_interp = /\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b/ ascii wide nocase

    condition:
        filesize < 2MB
        and ($reg_add or $ps_set)
        and any of ($target_*)
}
