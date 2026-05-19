rule Mimikatz_Credential_Dumper {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1003"
        family      = "Mimikatz"
    strings:
        $a = "mimikatz"          nocase
        $b = "sekurlsa::logonpasswords"  nocase
        $c = "lsadump::sam"     nocase
        $d = "Benjamin DELPY"
        $e = "Pass-the-hash"    nocase
    condition:
        2 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1071"
        family      = "CobaltStrike"
    strings:
        $a = "ReflectiveLoader"
        $b = "beacon"           nocase
        $c = { 4D 5A 90 00 03 00 00 00 }
        $d = "EICAR_COBALT"
    condition:
        $a or $d or ($b and $c)
}

rule Generic_Webshell {
    meta:
        description = "Detects common PHP/ASP webshell patterns"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1505.003"
        family      = "Webshell"
    strings:
        $php1 = "<?php eval(" nocase
        $php2 = "base64_decode($_" nocase
        $php3 = "passthru($_" nocase
        $asp1 = "<%eval request(" nocase
    condition:
        any of them
}