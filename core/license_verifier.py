# core/license_verifier.py

import hashlib
import hmac

class LicenseVerifier:
    # MUST match the generator's key
    # In a real enterprise app, you would obfuscate this or use RSA Public Keys
    MASTER_SECRET_KEY = "FMSecure_2026_Secret_Business_Key_$#@"

    @staticmethod
    def verify_license(user_email, license_key):
        """
        Verifies if a license key is valid for the given user.
        Returns: (is_valid, tier)
        """
        try:
            # 1. Parse the key
            # Format: TIER-EMAIL_HASH-SIGNATURE
            parts = license_key.strip().split('-')
            if len(parts) != 3:
                return False, "free"
                
            tier_tag, email_hash_tag, signature = parts
            tier = tier_tag.lower()
            user_id = user_email.strip().lower()
            
            # 2. Re-create the payload
            payload = f"{tier}:{user_id}"
            
            # 3. Re-calculate the expected signature
            expected_signature = hmac.new(
                LicenseVerifier.MASTER_SECRET_KEY.encode(), 
                payload.encode(), 
                hashlib.sha256
            ).hexdigest()[:16].upper()
            
            # 4. Verify Signature
            if hmac.compare_digest(signature, expected_signature):
                return True, tier
            
            return False, "free"
            
        except Exception as e:
            print(f"License Check Error: {e}")
            return False, "free"

# Singleton
license_verifier = LicenseVerifier()