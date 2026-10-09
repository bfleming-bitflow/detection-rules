rule LSASS_Memory_Dump_Command
{
    meta:
        id = "2daee922-0d6a-42d3-b92d-598a411ebd18"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "Script content that dumps LSASS process memory using comsvcs.dll MiniDump through rundll32 or Sysinternals ProcDump"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        reference2 = "https://lolbas-project.github.io/lolbas/Libraries/comsvcs/"
        mitre_attack = "T1003.001"
        severity = "high"
        false_positives = "Documented troubleshooting procedures that capture an LSASS dump at the request of a vendor"
        license = "DRL 1.1"

    strings:
        $comsvcs = /\bcomsvcs(\.dll)?["']?\s*,\s*["']?(MiniDump(W)?|#\+?24)\b/ ascii wide nocase
        $procdump = /\bprocdump(64)?(\.exe)?\s+[^\r\n]{0,60}-ma\s+[^\r\n]{0,30}\blsass(\.exe)?\b/ ascii wide nocase
        $procdump_r = /\bprocdump(64)?(\.exe)?\s+[^\r\n]{0,60}\blsass(\.exe)?\b[^\r\n]{0,60}-ma\b/ ascii wide nocase

    condition:
        filesize < 2MB
        and any of them
}
