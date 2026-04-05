import subprocess
import time
import os
import shutil
import sys
import socket

# Configuration
LAGO_BIN = os.path.abspath("target_new/debug/lago")
TEST_DIR = os.path.abspath("tmp_e2e_test")
DATA_DIR = os.path.join(TEST_DIR, ".lago")
GRPC_PORT = 50055
HTTP_PORT = 8085

def run_lago(args, background=False):
    cmd = [LAGO_BIN] + args
    print(f"Running: {' '.join(cmd)}")
    if background:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {result.stderr}")
        return result

def wait_for_port(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) == 0:
                return True
        time.sleep(0.5)
    return False

def cleanup():
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

def main():
    print("--- Starting E2E Test ---")
    
    # 1. Setup
    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)
    
    # 2. Init
    print("\n[Step 1] Initializing project...")
    res = run_lago(["init", TEST_DIR])
    if res.returncode != 0:
        print("FAIL: Init failed")
        sys.exit(1)
    
    # 3. Serve
    print("\n[Step 2] Starting server...")
    server_proc = run_lago([
        "serve", 
        "--data-dir", DATA_DIR, 
        "--grpc-port", str(GRPC_PORT), 
        "--http-port", str(HTTP_PORT)
    ], background=True)
    
    if not wait_for_port(HTTP_PORT):
        print("FAIL: Server failed to start")
        server_proc.kill()
        sys.exit(1)
    print("Server is running.")
    time.sleep(5)  # Wait for server to be ready

    try:
        # 4. Create Session
        print("\n[Step 3] Creating session...")
        res = run_lago([
            "--data-dir", DATA_DIR, 
            "--api-port", str(HTTP_PORT),
            "session", "create", 
            "--name", "e2e-session"
        ])
        if res.returncode != 0:
            print(f"FAIL: Session create failed: {res.stderr}")
            print(f"STDOUT: {res.stdout}")
            sys.exit(1)
        print("Session created.")

        # 5. List Sessions
        print("\n[Step 4] Listing sessions...")
        res = run_lago([
            "--data-dir", DATA_DIR, 
            "--api-port", str(HTTP_PORT),
            "session", "list"
        ])
        if res.returncode != 0:
            print(f"FAIL: Session list failed: {res.stderr}")
            sys.exit(1)
        
        print("Output:")
        print(res.stdout)
        
        if "e2e-session" in res.stdout:
            print("SUCCESS: Session found in list.")
        else:
            print("FAIL: Session not found in list.")
            sys.exit(1)

    finally:
        print("\n[Step 5] cleanup...")
        server_proc.terminate()
        server_proc.wait()
        cleanup()
        print("Done.")

if __name__ == "__main__":
    main()
