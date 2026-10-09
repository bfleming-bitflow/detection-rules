rule WebShell_ASPX_Process_Start_Request_Input
{
    meta:
        id = "98c65ede-e3cd-48c2-871a-3a43981d5176"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "ASP.NET page that starts an operating system process and reads HTTP request input, the core pattern of ASPX command web shells"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        reference2 = "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start"
        mitre_attack = "T1505.003"
        severity = "high"
        false_positives = "Internal administration pages that run fixed maintenance commands; review whether request input reaches the process arguments"
        license = "DRL 1.1"

    strings:
        $page = /<%@\s*Page\b/ ascii nocase
        $proc1 = "Process.Start" ascii nocase
        $proc2 = "ProcessStartInfo" ascii nocase
        $req1 = "Request.Form" ascii nocase
        $req2 = "Request.QueryString" ascii nocase
        $req3 = /Request\s*\[\s*"/ ascii nocase
        $req4 = "Request.Params" ascii nocase

    condition:
        filesize < 512KB
        and $page
        and any of ($proc*)
        and any of ($req*)
}
