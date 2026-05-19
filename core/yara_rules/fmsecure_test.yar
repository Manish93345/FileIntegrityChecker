/*
    TEST RULE — Safe to trigger for testing purposes.
    This rule matches the EICAR test string used by all AV vendors.
    Create a text file containing:  EICAR-STANDARD-ANTIVIRUS-TEST-FILE
    and FMSecure should immediately flag it as CRITICAL.
    Delete this file in production if you don't want test matches.
*/

rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file — safe test trigger"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1204"
        family      = "EICAR_Test"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}