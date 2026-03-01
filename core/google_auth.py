import os
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- SCOPES FOR SINGLE SIGN-ON ---
# We are asking Google for the user's email and basic profile info
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
CREDENTIALS_FILE = 'credentials.json.json'

def authenticate_google_sso():
    """
    Pops open a browser, securely authenticates the user via Google, 
    and returns their verified email address and name.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        return False, "credentials.json is missing! Cannot connect to Google."

    try:
        print("🔐 [GOOGLE SSO] Initializing secure login flow...")
        
        # Start the local web server to catch the Google login token
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        
        # This forces the browser to open and ask the user to choose their Google account
        creds = flow.run_local_server(port=0)

        # Build the userinfo service to read who just logged in
        user_info_service = build('oauth2', 'v2', credentials=creds)
        user_info = user_info_service.userinfo().get().execute()

        email = user_info.get('email')
        name = user_info.get('name', 'Google User')

        print(f"✅ [GOOGLE SSO] Success! Authenticated as: {email}")
        return True, {"email": email, "name": name}
        
    except Exception as e:
        print(f"❌ [GOOGLE SSO] Authentication failed: {e}")
        return False, f"Google Login Failed: {str(e)}"

# --- Quick Local Test ---
if __name__ == "__main__":
    success, result = authenticate_google_sso()
    if success:
        print(f"Test Passed! Hello, {result['name']} ({result['email']})")
    else:
        print(f"Test Failed: {result}")