# version.py — FMSecure Client
# ─────────────────────────────────────────────────────────────────────
# FULL RELEASE CHECKLIST (takes 3 minutes):
#   1. Bump APP_VERSION here
#   2. Update DRIVE_FILE_ID with the new Google Drive file ID
#   3. Go to Railway dashboard → Publish Version panel → save same version
#   4. Rebuild EXE with PyInstaller
# That's it. Every window, banner, and log reads from this file.
# ─────────────────────────────────────────────────────────────────────

APP_VERSION   = "2.5.0"
APP_NAME      = "FMSecure"
UPDATE_SERVER = "https://fmsecure-c2-server-production.up.railway.app"

# ── The Google Drive file ID for the latest EXE ──────────────────────
# When you upload a new EXE to Drive, copy its ID here.
# The ID is the long string in the Drive share URL:
#   https://drive.google.com/file/d/THIS_PART_HERE/view
DRIVE_FILE_ID = "1UgvEKLqzlx_CdpsLUQTDV-f4qmSYvjBg"   # ← only line to change

# ── Auto-derived URLs (do not edit these) ────────────────────────────
DOWNLOAD_PAGE_URL = f"{UPDATE_SERVER}/download"          # product/pricing page
DIRECT_DOWNLOAD_URL = (
    f"https://drive.google.com/uc?export=download&id={DRIVE_FILE_ID}"
)
CHANGELOG_URL = f"{UPDATE_SERVER}/changelog"