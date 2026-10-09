rule Certutil_Download_Or_Decode_Command
{
    meta:
        id = "29bf44e4-26a3-4010-9168-00052568f3a2"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "Script content that uses certutil to download a file from a URL or to decode a Base64 or hex encoded file"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"
        reference2 = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil"
        mitre_attack = "T1105, T1140"
        severity = "high"
        false_positives = "PKI administration scripts that fetch CRLs, and build scripts that decode embedded certificates"
        license = "DRL 1.1"

    strings:
        $download = /\bcertutil(\.exe)?\s+[^\r\n]{0,80}[-\/](urlcache|verifyctl)\b[^\r\n]{0,80}https?:\/\// ascii wide nocase
        $decode = /\bcertutil(\.exe)?\s+[^\r\n]{0,40}[-\/]decode(hex)?\s+\S+\s+\S+/ ascii wide nocase

    condition:
        filesize < 2MB
        and any of them
}
