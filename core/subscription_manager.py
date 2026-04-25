"""
core/subscription_manager.py — FMSecure v2.0
Central authority for what each tier can and cannot do.

Tiers:
  free          — 1 folder, no active defense, no cloud sync
  pro_monthly   — Full PRO features, billed monthly via Stripe
  pro_annual    — Full PRO features, billed annually (same features, different billing)

This module is intentionally kept stateless — it just maps tier strings to
feature flags. Tier detection lives in auth_manager.get_user_tier().
"""


class SubscriptionManager:

    TIERS = {
        "free": {
            "label":               "Free Plan",
            "max_folders":         1,
            "active_defense":      False,
            "ransomware_ks":       False,
            "cloud_sync":          False,
            "usb_control":         False,
            "can_export_pdf":      True,
            "can_access_api":      False,
            "forensic_vault":      False,
        },
        "pro_monthly": {
            "label":               "PRO Monthly",
            "max_folders":         5,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        "pro_annual": {
            "label":               "PRO Annual",
            "max_folders":         5,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        # Legacy alias — if old static keys still exist in users.dat
        "pro": {
            "label":               "PRO",
            "max_folders":         5,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        "premium": {
            "label":               "PRO",
            "max_folders":         5,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        # ── Org / Tenant tiers (server returns these for enrolled machines) ──────
        "business": {
            "label":               "Business",
            "max_folders":         10,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        "enterprise": {
            "label":               "Enterprise",
            "max_folders":         20,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        "trial": {
            "label":               "Trial",
            "max_folders":         3,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
        "org_pro": {
            "label":               "Org PRO",
            "max_folders":         10,
            "active_defense":      True,
            "ransomware_ks":       True,
            "cloud_sync":          True,
            "usb_control":         True,
            "can_export_pdf":      True,
            "can_access_api":      True,
            "forensic_vault":      True,
        },
    }

    @staticmethod
    def _resolve(tier: str) -> dict:
        """Normalise tier string and return its feature dict."""
        t = (tier or "free").strip().lower()
        return SubscriptionManager.TIERS.get(t, SubscriptionManager.TIERS["free"])

    @staticmethod
    def get_limits(tier: str) -> dict:
        return SubscriptionManager._resolve(tier)

    @staticmethod
    def is_pro(tier: str) -> bool:
        """True for any paid tier."""
        return SubscriptionManager._resolve(tier).get("can_access_api", False)

    @staticmethod
    def get_folder_limit(tier: str) -> int:
        return SubscriptionManager._resolve(tier).get("max_folders", 1)

    @staticmethod
    def can_add_folder(tier: str, current_count: int) -> bool:
        return current_count < SubscriptionManager.get_folder_limit(tier)

    @staticmethod
    def get_label(tier: str) -> str:
        return SubscriptionManager._resolve(tier).get("label", "Free Plan")

    @staticmethod
    def can_use(tier: str, feature: str) -> bool:
        """
        Generic feature gate.
        feature must be a key in the TIERS dict, e.g.:
          subscription_manager.can_use(tier, 'active_defense')
          subscription_manager.can_use(tier, 'cloud_sync')
        """
        return bool(SubscriptionManager._resolve(tier).get(feature, False))


# Singleton
subscription_manager = SubscriptionManager()