# Carlos Rodriguez
# Secure Chat – CSC380 Final Project

This is a secure peer-to-peer chat application developed as a final project for CSC380: Computer Security. It demonstrates core cryptographic principles such as mutual authentication, message confidentiality, integrity, and replay protection.

## Project Features

- **Mutual Authentication**: RSA-based challenge-response
- **Perfect Forward Secrecy**: 3DH key exchange (using both ephemeral and long-term keys)
- **Confidentiality**: AES-256-GCM message encryption
- **Integrity**: HMAC-SHA256 for message authentication
- **Replay Attack Defense**: Timestamp-based nonce validation

---

## Requirements

To compile and run this project, you’ll need:

- GCC or Clang (C Compiler)
- GTK+ 3 development libraries
- OpenSSL development libraries
- GMP development libraries

**Ubuntu/Debian:**
```bash
sudo apt install libgtk-3-dev libssl-dev libgmp-dev build-essential
```

---

## Build Instructions

```bash
make
```

This compiles the project and produces the executable `chat`.

---

## Running the Application

### Start a Server:
```bash
./chat -l
```

### Start a Client:
```bash
./chat -c localhost
```

After a brief moment, both windows will be connected securely.

---

## RSA Keys

This project assumes the RSA keys have been pre-exchanged:

- `client_private.pem`, `client_public.pem`
- `server_private.pem`, `server_public.pem`

These are included in the repository for demo/testing purposes. In real applications, securely generate and store keys.

---

## File Overview

| File | Description |
|------|-------------|
| `chat.c` | Main program logic |
| `dh.c/h`, `keys.c/h`, `util.c/h` | Cryptographic support |
| `params` | DH parameters (q, p, g) |
| `layout.ui`, `colors.css` | GTK UI layout and styling |
| `Makefile` | Build script |
| `security_document.txt` | Write-up describing security model |
| `*.pem` | RSA public/private keypairs for both sides |

---

## Security Summary

- RSA-based mutual authentication
- AES-GCM with ephemeral session keys for encryption
- HMAC-SHA256 for message integrity
- Nonce tracking to prevent message replays

See `security_document.txt` for the full explanation.

---
