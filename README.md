# autosync
A lightweight resumable file upload &amp; sync server with PAT/JWT authentication, written in Go.

AutoSync is a lightweight file sync and upload server written in Go.  
It supports **resumable uploads**, **SHA-256 verification**, **file management**, and simple **API authentication** using Personal Access Tokens (PAT) or JWT.

## Features
- 🚀 Resumable uploads with chunking (`Content-Range`)
- 🔐 Authentication via **PAT** or **JWT**
- 📂 File operations (Upload, Move, Delete, List)
- ✅ SHA-256 integrity check & ETag support
- 🛡️ Secure path handling (prevents path traversal)

## Configuration
Environment variables:
```env
PAT_TOKENS=token1,token2
FIXED_PAT=Drive-Sync
JWT_SECRET=please-change-me
DATA_DIR=/srv/autosync/data
UPLOADS_DIR=/srv/autosync/uploads
PORT=8080
