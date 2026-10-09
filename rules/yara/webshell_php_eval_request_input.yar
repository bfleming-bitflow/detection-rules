rule WebShell_PHP_Eval_Request_Input
{
    meta:
        id = "7808643d-4515-4b5b-8708-e1910a71d4cb"
        author = "bfleming-bitflow"
        date = "2026-10-09"
        description = "PHP file that passes HTTP request input directly to a code or command execution function, the core pattern of minimal PHP web shells"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        reference2 = "https://github.com/nsacyber/Mitigating-Web-Shells"
        mitre_attack = "T1505.003"
        severity = "high"
        false_positives = "Deliberately vulnerable training applications and security test suites"
        license = "DRL 1.1"

    strings:
        $php_open = "<?php" ascii nocase
        $php_short = "<?=" ascii
        // An execution sink receiving a superglobal, optionally through a decoding wrapper.
        $sink = /\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?((base64_decode|str_rot13|gzinflate|gzuncompress|stripslashes|urldecode|hex2bin)\s*\(\s*)*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ ascii nocase
        $backtick = /`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*`/ ascii

    condition:
        filesize < 512KB
        and ($php_open or $php_short)
        and ($sink or $backtick)
}
