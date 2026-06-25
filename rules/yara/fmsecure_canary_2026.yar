rule FMSecure_Canary_2026
{
    meta:
        author       = "fmsecure-test"
        description  = "Deployment canary — fires on a known test marker"
        date         = "2026-06-21"
        severity     = "INFO"

    strings:
        $marker = "FM-CANARY-DO-NOT-USE-IN-PROD-d4f1c2a8"

    condition:
        $marker
}