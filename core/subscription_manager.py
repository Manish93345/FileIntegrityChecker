# core/subscription_manager.py

class SubscriptionManager:
    """
    Manages feature limits based on user tiers.
    Central place to define what Free vs Premium users can do.
    """
    
    # Define the capabilities for each tier
    TIERS = {
        "free": {
            "max_folders": 1,
            "can_export_pdf": True,
            "can_access_api": False,
            "label": "Free Plan"
        },
        "premium": {
            "max_folders": 5,
            "can_export_pdf": True,
            "can_access_api": True,
            "label": "PRO License"
        }
    }

    @staticmethod
    def get_limits(tier):
        """Get the dictionary of limits for a specific tier"""
        # Default to 'free' if the tier string is invalid
        return SubscriptionManager.TIERS.get(tier, SubscriptionManager.TIERS["free"])

    @staticmethod
    def get_folder_limit(tier):
        """Return max folders allowed for this tier"""
        limits = SubscriptionManager.get_limits(tier)
        return limits.get("max_folders", 1)

    @staticmethod
    def can_add_folder(tier, current_count):
        """Check if user can add more folders"""
        limit = SubscriptionManager.get_folder_limit(tier)
        return current_count < limit

# Singleton instance (optional, but good practice)
subscription_manager = SubscriptionManager()