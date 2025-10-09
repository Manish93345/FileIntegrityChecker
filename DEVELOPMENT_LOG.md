### 7 Oct 2025
- Created project folder and structure
- Wrote initial README.md
- Planned tech stack and features with Lisa 💞


    hash_generation.py
        It is just a simple program to check whether it is generating hash of a file or not. 


    Now created first file_checker.py 
        This is for only one file, like we give the path of a file and it first saves tha hash value of the file.
        Now if the file will tampered later then we can detect it using the same program. 
    

    folder_monitor.py
        This is a polling based integrity checker. Polling based means that program will check the specific folder (./tests) that if the 
        file inside that folder is modified, deleted or new file added or not. It will create two files -> integrity_log.txt and hash_record.json. 




### 8 Oct 2025
    -For real time monitoring
    -Install watchdog -> pip install watchdog
    -realtime_monitor.py
    