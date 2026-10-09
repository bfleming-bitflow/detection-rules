rule PowerShell_Download_Cradle
{
    meta:
        id = "01b695b2-dde3-4236-948b-964a4501ecaa"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "PowerShell content that downloads a remote script and executes it in memory with Invoke-Expression"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        reference2 = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression"
        mitre_attack = "T1059.001, T1105"
        severity = "high"
        false_positives = "Installer one-liners published by software vendors (for example package manager bootstrap scripts); these are still worth reviewing on servers"
        license = "DRL 1.1"

    strings:
        // IEX (New-Object Net.WebClient).DownloadString('...')
        $webclient_iex = /\b(iex|Invoke-Expression)\b[\s(]{0,10}New-Object\s+(System\.)?Net\.WebClient\s*\)?\s*\.\s*Download(String|Data)\s*\(/ ascii wide nocase
        // (New-Object Net.WebClient).DownloadString('...') | IEX
        $webclient_pipe = /\.\s*DownloadString\s*\([^\r\n)]{1,300}\)\s*\)?\s*\|\s*(iex|Invoke-Expression)\b/ ascii wide nocase
        // iwr / irm ... | iex
        $iwr_pipe = /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n|]{1,300}\|\s*(iex|Invoke-Expression)\b/ ascii wide nocase
        // IEX (iwr ...).Content or IEX (irm ...)
        $iex_iwr = /\b(iex|Invoke-Expression)\b[\s(]{1,10}(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/ ascii wide nocase

    condition:
        filesize < 2MB
        and any of them
}
