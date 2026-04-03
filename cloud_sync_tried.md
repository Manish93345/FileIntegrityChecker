# Problem 
    The cloud sync feature is working perfectly when I run the code from vs code. But when I create an exe file and run it, the cloud sync is not working.
    When from the vs code part token.pickle i am pasting to the users -> kumar -> appdata -> local -> secureFM
    then the cloud sync is working perfectly. But when the new freesh tocken.pickle is created in the secureFM folder, when the app is installed first time, then cloud sync is getting stuck also on the google drive no any folder is getting created for it. 

## METHOD THAT ARE ALREADY TRIED

### METHOD 1:
    Root Cause 1: token.pickle Path Mismatch (Primary Issue)
    Look at your utils.py:
    pythondef get_app_data_dir():
        if getattr(sys, 'frozen', False):
            # EXE → %LOCALAPPDATA%\SecureFIM
            app_data = os.path.join(os.environ.get("LOCALAPPDATA", ...), "SecureFIM")
        # Script → project root directory
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    And in cloud_sync.py:
    pythonTOKEN_FILE = os.path.join(get_app_data_dir(), 'token.pickle')
    When running from VS Code: token.pickle lives in your project root folder.
    When running as EXE: it looks for token.pickle in %LOCALAPPDATA%\SecureFIM\.
    That's exactly why manually copying it fixes the problem — you're bridging the path gap.
    Root Cause 2: ThreadPoolExecutor Hanging (Why it sticks at 2/44)
    The EXE does get a token (via force_authenticate()), starts uploading, then freezes. This is a PyInstaller threading + Google API dependency issue. The _get_safe_service() method creates thread-local Drive service instances via build(), and googleapiclient relies on internal discovery/HTTP libraries that PyInstaller doesn't bundle automatically. One thread silently fails, and as_completed() hangs waiting for a Future that never resolves.

    The Fix
    Fix 1 — Auto-migrate token on first EXE launch
    In cloud_sync.py, update _authenticate_background():
    pythondef _authenticate_background(self, interactive=False):
        from core.utils import get_app_data_dir
        TOKEN_FILE = os.path.join(get_app_data_dir(), 'token.pickle')
        
        # ── ONE-TIME MIGRATION: copy token from old script location ──────────
        if not os.path.exists(TOKEN_FILE):
            old_locations = [
                os.path.join(os.path.dirname(sys.executable), 'token.pickle'),
                os.path.join(os.getcwd(), 'token.pickle'),
            ]
            # If running frozen, also check parent dirs
            if getattr(sys, 'frozen', False):
                old_locations.append(
                    os.path.join(os.path.dirname(os.path.dirname(sys.executable)), 'token.pickle')
                )
            for old_path in old_locations:
                if os.path.exists(old_path):
                    try:
                        import shutil
                        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
                        shutil.copy2(old_path, TOKEN_FILE)
                        print(f"☁️  Token migrated from {old_path}")
                        break
                    except Exception as e:
                        print(f"☁️  Token migration failed: {e}")
        # ─────────────────────────────────────────────────────────────────────
        
        creds = None
        try:
            # ... rest of your existing auth code
    Fix 2 — Add a timeout to batch_upload so it never hangs
    In cloud_sync.py, update batch_upload():
    pythondef batch_upload(self, file_paths: list, folder_id: str,
                    progress_cb=None, max_workers: int = 4) -> dict:
        if not self.is_active:
            return {'uploaded': 0, 'failed': len(file_paths), 'errors': ['Cloud offline']}

        total    = len(file_paths)
        uploaded = 0
        failed   = 0
        errors   = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {
                pool.submit(self._upload_one_file, fp, folder_id): fp
                for fp in file_paths
            }
            for future in as_completed(future_map, timeout=120):  # 🚨 ADD TIMEOUT
                fp   = future_map[future]
                name = os.path.basename(fp)
                try:
                    if future.result(timeout=30):  # 🚨 PER-FILE TIMEOUT
                        uploaded += 1
                    else:
                        failed += 1
                        errors.append(name)
                except Exception as e:
                    failed += 1
                    errors.append(f"{name}: {e}")

                if progress_cb:
                    try:
                        progress_cb(uploaded, total, name)
                    except Exception:
                        pass

        return {'uploaded': uploaded, 'failed': failed, 'errors': errors}
    Fix 3 — Rebuild the EXE with missing Google dependencies
    This is the real fix for the thread hanging. PyInstaller misses several Google API internals:
    bashpyinstaller run.py `
    --onedir `
    --noconsole `
    --name SecureFIM `
    --icon=assets/icons/app_icon.ico `
    --add-data "assets;assets" `
    --collect-all google `
    --collect-all googleapiclient `
    --collect-all google_auth_oauthlib `
    --collect-all httplib2 `
    --collect-all certifi `
    --hidden-import=google.auth.transport.requests `
    --hidden-import=google.oauth2.credentials `
    --hidden-import=googleapiclient.discovery `
    --hidden-import=googleapiclient.http `
    --clean
    The --collect-all certifi is critical — without bundled SSL certificates, HTTPS calls to Google's API silently fail inside PyInstaller's frozen environment, which is exactly the behaviour you're seeing (partial success then hang).
    Fix 4 — Make _get_safe_service() more resilient in frozen mode
    pythondef _get_safe_service(self):
        if not self.is_active or not self.creds:
            return None
        if not hasattr(_thread_local, 'service') or _thread_local.service is None:
            try:
                # In frozen EXE, disable discovery cache entirely
                _thread_local.service = build(
                    'drive', 'v3',
                    credentials=self.creds,
                    cache_discovery=False,
                    num_retries=3          # 🚨 ADD: auto-retry on transient failures
                )
            except Exception as e:
                print(f"☁️  Thread-local service build failed: {e}")
                return None
        return _thread_local.service

    Quick Validation Checklist
    After rebuilding with the new PyInstaller command, test this sequence without copying any token manually:

    Delete %LOCALAPPDATA%\SecureFIM\token.pickle completely
    Run fresh EXE → click "Sync to Cloud"
    Browser opens → authenticate → token should now save to %LOCALAPPDATA%\SecureFIM\token.pickle
    Uploads should complete all 44 files without hanging

    The combination of the --collect-all flags and the per-future timeout means even if one thread has an SSL hiccup, the overall upload won't freeze — it'll just mark that file as failed and move on, which is the correct enterprise-grade behaviour.





### METHOD 2
    The debug log reveals the exact root cause. I can diagnose this precisely now.
    The Real Problem: _get_or_create_folder() is being called from multiple concurrent threads simultaneously on the same path, causing a race condition that creates an infinite loop of GET → POST → GET → POST.
    Look at lines 233–256 in your log. After authentication succeeds, the same folder query (FMSecure_FM-1E5284B6927C94A025E9B954) fires in parallel from multiple threads — every thread gets a cache miss simultaneously (because the folder doesn't exist yet), every thread tries to create it concurrently, and the folder-ID cache never gets written cleanly because each thread's _get_or_create_folder() races through the cache-write. The result is the infinite GET/POST loop you see — it never moves past creating the root folder.
    This is a classic double-checked locking failure in the folder creation path. The _cache_lock guards the read of self._folder_cache, but the Drive API call and the cache write happen outside the lock, so under ThreadPoolExecutor(max_workers=4), all 4 workers hit the cache miss at exactly the same time, all call service.files().create(), and all compete to write the result back.
    Here's the precise fix — a proper per-folder mutex so only one thread ever creates a given folder, and the others wait and use the result:Reading cloud_sync.py folder creation methodReading cloud_sync.py folder creation methodNow I have the full picture. Here is the production-grade fix. The solution is two-pronged:
    Problem 1 (the infinite loop in the log): _get_or_create_folder() holds _cache_lock only for the cache read, but the Drive API call and cache write happen outside it. Under 4 concurrent workers, all 4 threads see a cache miss simultaneously, all call files().create(), and the cache never stabilizes — infinite GET/POST loop.
    Problem 2 (why VS Code works but EXE doesn't): googleapiclient.discovery.build() fetches a discovery document from https://www.googleapis.com/discovery/v1/apis/drive/v3/rest on first call. In VS Code this gets cached on disk. In the frozen EXE, the default cache location (~/.cache/googleapiclient-discovery) fails silently because PyInstaller's temp directory is read-only or gets cleaned, so every build() call re-fetches the document — this is a second network hit happening concurrently from all 4 threads, each one racing the others. Combined with Problem 1, the EXE deadlocks completely.
    The fix is a proper per-folder creation lock (industry pattern: serialize folder provisioning, parallelize file uploads) and explicit discovery document caching to a writable path:Reading the _get_or_create_folder and build callsReading the _get_or_create_folder and build callsThe diagnosis is confirmed. Now I'll write the complete fixed cloud_sync.py:Reading rest of cloud_sync.pyReading rest of cloud_sync.pyNow I have everything I need. Here's the complete diagnosis and the precise surgical fix:
    Root cause summary from the log:

    The infinite GET/POST loop (lines 233–256): _get_or_create_folder() reads the cache under _cache_lock but then releases the lock before the Drive API call. Under 4 concurrent ThreadPoolExecutor workers, all 4 threads see a cache miss simultaneously, all proceed to call service.files().list() (the GET), all find the folder doesn't exist, all try service.files().create() (the POST), and all try to write to the cache. This creates the repeating GET→POST→GET→POST you see in the log — it never settles because the race condition keeps producing duplicate creation attempts that Drive throttles or rejects.
    Why the _file_lock in _upload_one_file also makes it worse: The entire upload path is serialized through one process-wide lock, so folder creation and file uploads compete for the same lock — further deadlocking under concurrent workers.
    Why VS Code works but EXE doesn't: In VS Code, build('drive', 'v3') uses the system-level googleapiclient discovery cache at ~/.cache/. In the frozen EXE, that cache path either doesn't exist in sys._MEIPASS or is read-only, so every thread rebuilds the service from scratch with a fresh network call to Google's discovery endpoint — adding latency that widens the race window enough to always reproduce it.

    The fix is: per-key folder creation locks (not a global lock) so concurrent threads serialize on the specific path they're creating, plus fix _get_safe_service to gracefully handle service rebuild in the EXE, and remove the global _file_lock that serializes uploads unnecessarily.Created a file, read a fileCreated a file, read a fileHere's the complete breakdown of exactly what was wrong and what was fixed.

    What the debug log revealed
    Lines 233–256 of your log show the exact failure signature — after a successful OAuth token exchange (line 232 confirms ONLINE), the same Drive query fires in a tight loop every ~1 second, alternating GET and POST indefinitely:
    GET  /drive/v3/files?q=name='FMSecure_FM-...'  (folder doesn't exist yet)
    POST /drive/v3/files  (try to create it)
    GET  /drive/v3/files?q=name='FMSecure_FM-...'  (still doesn't exist?)
    POST /drive/v3/files  (try again)
    ...
    This is the race condition in _get_or_create_folder().

    Root cause #1 — The race condition (the primary bug)
    The old code released _cache_lock before making the Drive API call:
    pythonwith self._cache_lock:          # lock released here ↓
        if key in self._folder_cache:
            return self._folder_cache[key]
    # ← LOCK IS GONE. All 4 ThreadPoolExecutor workers are now here simultaneously.
    service.files().list(...)       # all 4 see "folder doesn't exist"
    service.files().create(...)     # all 4 try to create it
    with self._cache_lock:
        self._folder_cache[key] = fid  # all 4 write different IDs, nothing settles
    Under ThreadPoolExecutor(max_workers=4), all 4 workers hit the cache miss at the same instant. All 4 call files().list(), all see the folder doesn't exist, all call files().create(). Drive's API either rate-limits the duplicate creates or creates duplicates — either way the response IDs differ between threads, the cache never stabilizes, and the loop continues.
    The fix is a two-level locking strategy used in distributed systems for idempotent resource provisioning — a fast path (cache read) plus a per-key creation lock with a mandatory double-check inside it:
    python# Fast path — no I/O
    with self._cache_lock:
        if key in self._folder_cache:
            return self._folder_cache[key]

    # Slow path — only ONE thread per key ever reaches Drive
    with self._get_creation_lock(key):    # per-key, not global
        with self._cache_lock:            # double-check after acquiring
            if key in self._folder_cache:
                return self._folder_cache[key]
        # Only one thread calls Drive. Others wait, then hit the double-check.
        fid = drive_api_call()
        with self._cache_lock:
            self._folder_cache[key] = fid

    Root cause #2 — The global _file_lock made it worse
    The old _upload_one_file held a single process-wide _file_lock around every upload, meaning all 4 ThreadPoolExecutor workers serialized onto one thread for file uploads too. When the folder creation loop stalled, no upload thread could make progress — the lock was held by the stalled folder-creation thread. This is why it appeared completely frozen rather than just slow.
    The fix removes the global lock. Individual file uploads are safe to run concurrently because each operates on a different remote filename.

    Root cause #3 — EXE-specific _get_safe_service() fragility
    In VS Code, googleapiclient.discovery.build() uses the system-level discovery document cache at ~/.cache/googleapiclient-discovery. In the frozen EXE, PyInstaller's temp directory (sys._MEIPASS) is read-only, so build() falls back to a network fetch of Google's discovery document on every call — adding ~200ms of latency per thread, which widens the race window from essentially zero in VS Code to wide enough to always reproduce in the EXE.
    The fix adds a graceful fallback: if a worker thread can't build its own service instance, it falls back to the main-thread service rather than returning None and silently dropping the upload.

    How to deploy
    Replace core/cloud_sync.py in your project with the file above, then rebuild with the same PyInstaller command you're already using — no new --hidden-import flags needed. The fix is purely in the Python threading logic, not in missing dependencies.



### METHOD 3
    