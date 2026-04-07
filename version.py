# version.py — FMSecure Client
# ─────────────────────────────────────────────────────────────────────
# THIS IS THE ONLY PLACE YOU CHANGE THE VERSION NUMBER.
# When you release a new build:
#   1. Bump APP_VERSION here
#   2. Push to Railway dashboard → type new version + notes → Save
#   3. Rebuild your EXE
# That's it. Every window, log line, and update check reads from here.
# ─────────────────────────────────────────────────────────────────────

APP_VERSION   = "2.6.0"          # ← only line you ever edit
APP_NAME      = "FMSecure"
UPDATE_SERVER = "https://fmsecure-c2-server-production.up.railway.app"