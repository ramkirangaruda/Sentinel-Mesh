import os

# TestClient sends "Host: testserver"; the API only answers to the hosts in
# SENTINEL_ALLOWED_HOSTS (api/main.py, same_origin_only).
os.environ.setdefault("SENTINEL_ALLOWED_HOSTS", "127.0.0.1,localhost,::1,testserver")
