import os
import threading
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from core.integrity_core import CONFIG, append_log_line

# --- GOOGLE DRIVE OAUTH 2.0 CONFIGURATION ---
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_FILE = 'credentials.json.json'
TOKEN_FILE = 'token.pickle'
MASTER_FOLDER_ID = '' # <-- Keep your Folder ID here!

class CloudSyncManager:
    def __init__(self):
        self.service = None
        self.is_active = False
        self.upload_lock = threading.Lock() # <-- NEW: The Traffic Light
        self._authenticate_background()

    def _authenticate_background(self):
        """Authenticates using OAuth 2.0 (Pops open a browser the first time)"""
        creds = None
        
        try:
            # Check if we already have a saved login token
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'rb') as token:
                    creds = pickle.load(token)
            
            # If there are no (valid) credentials available, let the user log in.
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    if not os.path.exists(CREDENTIALS_FILE):
                        print("☁️ Cloud Sync: OFFLINE (credentials.json missing)")
                        return
                        
                    print("☁️ [CLOUD SYNC] First-time setup: Opening browser for authentication...")
                    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                    # This will open your web browser
                    creds = flow.run_local_server(port=0)
                
                # Save the credentials for the next run
                with open(TOKEN_FILE, 'wb') as token:
                    pickle.dump(creds, token)

            # Build the Drive service
            self.service = build('drive', 'v3', credentials=creds, cache_discovery=False)
            self.is_active = True
            print("☁️ Cloud Sync Engine: ONLINE (Authenticated as User)")
            
        except Exception as e:
            print(f"☁️ Cloud Sync Init Error: {e}")

    def _sanitize_email(self, email):
        if not email: return "Vault_Unregistered_User"
        safe_email = email.replace("@", "_").replace(".", "_")
        return f"Vault_{safe_email}"

    def _get_or_create_user_folder(self, folder_name):
        if not self.service: return None
        
        query = f"name='{folder_name}' and '{MASTER_FOLDER_ID}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
        results = self.service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        items = results.get('files', [])

        if items: return items[0]['id']
            
        file_metadata = {
            'name': folder_name,
            'parents': [MASTER_FOLDER_ID],
            'mimeType': 'application/vnd.google-apps.folder'
        }
        folder = self.service.files().create(body=file_metadata, fields='id').execute()
        return folder.get('id')

    def upload_encrypted_backup(self, local_file_path):
        if not self.is_active or not os.path.exists(local_file_path):
            return

        def _background_upload():
            # --- THE FIX: Force threads to wait in line! ---
            with self.upload_lock:
                try:
                    user_email = CONFIG.get("admin_email", "UnknownUser")
                    folder_name = self._sanitize_email(user_email)
                    folder_id = self._get_or_create_user_folder(folder_name)
                    
                    if not folder_id: return
                    
                    filename = os.path.basename(local_file_path)
                    query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
                    results = self.service.files().list(q=query, spaces='drive', fields='files(id)').execute()
                    items = results.get('files', [])

                    media = MediaFileUpload(local_file_path, resumable=True)

                    if items:
                        file_id = items[0]['id']
                        self.service.files().update(fileId=file_id, media_body=media).execute()
                        print(f"☁️ [CLOUD SYNC] Updated cloud backup: {filename}")
                    else:
                        file_metadata = {'name': filename, 'parents': [folder_id]}
                        self.service.files().create(body=file_metadata, media_body=media).execute()
                        print(f"☁️ [CLOUD SYNC] Uploaded new cloud backup: {filename}")
                        
                except Exception as e:
                    print(f"☁️ [CLOUD SYNC] UPLOAD FAILED: {e}")

        threading.Thread(target=_background_upload, daemon=True).start()

    def download_from_cloud(self, filename, local_dest_path):
        """Downloads a specific encrypted file from the user's Google Drive"""
        if not self.is_active: 
            return False
            
        try:
            # 1. Find the user's specific folder
            user_email = CONFIG.get("admin_email", "UnknownUser")
            folder_name = self._sanitize_email(user_email)
            folder_id = self._get_or_create_user_folder(folder_name)
            
            if not folder_id: return False
            
            # 2. Search for the file inside their folder
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            results = self.service.files().list(q=query, spaces='drive', fields='files(id)').execute()
            items = results.get('files', [])
            
            if not items:
                return False # The file is not in the cloud either!
                
            file_id = items[0]['id']
            
            # 3. Download the file
            import io
            from googleapiclient.http import MediaIoBaseDownload
            
            request = self.service.files().get_media(fileId=file_id)
            with open(local_dest_path, 'wb') as fh:
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
                    
            return True # Successfully downloaded!
            
        except Exception as e:
            print(f"☁️ [CLOUD SYNC] Download failed: {e}")
            return False

# Global instance
cloud_sync = CloudSyncManager()