# autosync
A lightweight resumable file upload &amp; sync server with PAT/JWT authentication, written in Go.

# AutoSync Server

AutoSync is a lightweight file synchronization and upload server written in Go.  
It provides a REST API for **chunked uploads**, **SHA256 validation**, and **token-based authentication**.  
Designed to be simple, fast, and secure.

---

## Features

- 🚀 Resumable file uploads
- 🔒 Authentication via **PAT tokens** or **JWT**
- 🗂️ File management: upload, list, move, delete
- ⚡ Minimal footprint (built with [chi router](https://github.com/go-chi/chi))

---

## Installation

### 1. Install a Linux distribution (or use an existing system)

### 2. Install Go

```bash
curl -fsSL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -o /tmp/go.tgz
sudo tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh
```

### 3. Setup user and directories
# Create service user
```bash
sudo groupadd autosync
sudo adduser --system --home /home/autosync --group autosync
```

# Project directory
```bash
sudo mkdir -p /opt/autosync
sudo chown -R autosync:autosync /opt/autosync
```
# Go build caches
```bash
sudo mkdir -p /var/lib/autosync/gopath /var/lib/autosync/gomodcache /var/lib/autosync/gocache
sudo chown -R autosync:autosync /var/lib/autosync
```

# Environment for Go caches
```bash
echo 'export GOPATH=/var/lib/autosync/gopath
export GOMODCACHE=/var/lib/autosync/gomodcache
export GOCACHE=/var/lib/autosync/gocache' | sudo tee /etc/profile.d/autosync.sh
```

### 4. Build the server
```bash
cd /opt/autosync

# Copy main.go into this directory first
sudo -u autosync -H bash -lc 'go mod init autosync && go mod tidy && go build -o autosync-server'
```

### 5. Data directories & environment file
```bash
sudo mkdir -p /srv/autosync/data /srv/autosync/uploads
sudo chown -R autosync:autosync /srv/autosync
```
# Environment config
```bash
sudo tee /etc/autosync.env >/dev/null <<'EOF'
DATA_DIR=/srv/autosync/data
UPLOADS_DIR=/srv/autosync/uploads
JWT_SECRET=change-me-please

# Optional personal access tokens (comma separated)

PAT_TOKENS=mypat1,mypat2
FIXED_PAT=Drive-Sync

# Go caches outside the project
```bash
GOPATH=/var/lib/autosync/gopath
GOMODCACHE=/var/lib/autosync/gomodcache
GOCACHE=/var/lib/autosync/gocache
EOF
```

### 6. Systemd service
```bash
sudo tee /etc/systemd/system/autosync.service >/dev/null <<'EOF'
[Unit]
Description=AutoSync Server (Go)
After=network.target

[Service]
User=autosync
Group=autosync
WorkingDirectory=/opt/autosync
EnvironmentFile=/etc/autosync.env
ExecStart=/opt/autosync/autosync-server
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now autosync.service
systemctl status autosync.service --no-pager
```

### Quick Test
```bash
curl -fsS http://127.0.0.1:8080/v1/health && echo
```

# Output: ok

### Upload (requires PAT)
```bash
curl -i -X POST http://127.0.0.1:8080/v1/uploads \
  -H 'Content-Type: application/json' \
  -H 'X-PAT: mypat1' \
  -d '{"path":"test/foo.bin","size":0,"sha256":"","overwrite":true}'
```

### (Optional) Reverse Proxy with Caddy (TLS)
# 1. install Caddy.
# 2. EDIT /etc/caddy/Caddyfile
```caddy
autosync.YOUR-DOMAIN.TLD {
    reverse_proxy 127.0.0.1:8080
    encode gzip zstd
    header {
        X-Frame-Options "DENY"
    }
}
```
