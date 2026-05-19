/*
    FMSecure YARA Rules — Ransomware Families
    These are simplified detection rules for common ransomware strings.
    Replace with full community rulesets from Elastic / THOR for production.
*/

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1486"
        family      = "WannaCry"
    strings:
        $a = "WannaCryptDecryptor" nocase
        $b = "tasksche.exe"        nocase
        $c = "msg/m_chinese"       nocase
        $d = "WNcry@2ol7"
    condition:
        2 of them
}

rule NotPetya_Ransomware {
    meta:
        description = "Detects NotPetya / Petya ransomware"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1486"
        family      = "NotPetya"
    strings:
        $a = "wevtutil cl Setup" nocase
        $b = "MBR infection"
        $c = "Chkdsk cannot continue in read-only mode"
        $d = { 77 61 6E 61 63 72 79 }
    condition:
        2 of them
}

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware strings"
        author      = "FMSecure"
        severity    = "CRITICAL"
        mitre       = "T1486"
        family      = "LockBit"
    strings:
        $a = "LockBit"         nocase
        $b = "lockbit_decryptor"
        $c = "All your files are encrypted"
        $d = ".lockbit"
    condition:
        2 of them
}