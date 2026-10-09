rule PowerShell_Encoded_Command_Launcher
{
    meta:
        id = "ec0b91c1-1b82-4cf0-8f44-60909dd0d5a2"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "Script, shortcut target or configuration file that launches PowerShell with an inline Base64 encoded command"
        reference = "https://attack.mitre.org/techniques/T1027/010/"
        reference2 = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe"
        mitre_attack = "T1059.001, T1027.010"
        severity = "medium"
        false_positives = "Management tooling that generates launcher scripts with encoded commands"
        license = "DRL 1.1"

    strings:
        // powershell[.exe] [other parameters] -e|-en|-enc...|-ec <base64 of at least 40 characters>
        $launcher = /\b(powershell|pwsh)(\.exe)?["']?(\s+[-\/][a-z]+(\s+[a-z0-9]+)?){0,6}\s+[-\/](e|en|enc[a-z]*|ec)\s+["']?[A-Za-z0-9+\/]{40,}={0,2}/ ascii wide nocase

    condition:
        filesize < 2MB
        and $launcher
}
