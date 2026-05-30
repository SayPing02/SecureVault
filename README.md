# SecureVault

A standalone Windows desktop application for **secure file storage and
sharing**. Files are encrypted with **AES-256-GCM** and split into
**k-of-n fragments** using **Shamir's Secret Sharing**. No internet
connection is required — everything happens on the local machine.

Built with a **Rust** backend and a **Tauri v2** frontend.

---

## Table of contents

1. [What the app does](#what-the-app-does)
2. [How the cryptography works](#how-the-cryptography-works)
3. [Project structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Running the app (Windows)](#running-the-app-windows)
6. [Building a Windows installer](#building-a-windows-installer)
7. [Development and testing with Docker](#development-and-testing-with-docker)
8. [The backend command API](#the-backend-command-api)
9. [Security notes and limitations](#security-notes-and-limitations)

---

## What the app does

SecureVault has four screens:

* **My Files** — lists everything stored in your vault. Click a file to
  reconstruct and download it; or use the buttons to **share** or
  **delete** it.
* **Add File** — pick a file, choose `N` (total fragments), `K`
  (threshold), and an optional password, then split it into the vault.
* **Import Shared** — load a `.zip` bundle another user sent you. The app
  rebuilds their file and re-stores it in *your* vault.
* **How It Works** — an explanation of the scheme.

### The typical flow

```
Add a file ──► encrypted + split into N fragments ──► stored in vault
                                                          │
        ┌─────────────────────────────────────────────────┤
        ▼                                                  ▼
   Download                                            Share
   (needs K fragments,                          (zips the minimum K
    reconstructs to Downloads)                   fragments to Downloads)
                                                          │
                                                          ▼
                                            another user runs "Import"
                                            ──► file rebuilt + re-split
                                                into their own vault
```

---

## How the cryptography works

A naive approach would run Shamir's Secret Sharing over every byte of the
file. That works, but it makes **each fragment as large as the whole
file** — ten fragments of a 50 MB file would be 500 MB. SecureVault uses
the standard **hybrid scheme** instead:

1. **Encrypt the file.** A random 256-bit key is generated and the entire
   file is encrypted once with **AES-256-GCM**. GCM also produces an
   authentication tag, so tampering is detected on decryption.

2. **Split only the key.** The small 32-byte AES key is the secret that
   gets **Shamir-split** into `N` shares. Each share is tiny.

3. **Optional password layer.** If the user sets a password, the AES key
   is itself encrypted (with a key derived from the password via
   **PBKDF2-HMAC-SHA256**) *before* being split. Now even someone holding
   `K` fragments cannot rebuild the file without the password.

4. **Package fragments.** Each `.svf` fragment file carries one key share,
   a copy of the ciphertext, and the metadata (`N`, `K`, nonce, salt,
   SHA-256 checksum). Any `K` fragments rebuild the file; any `K-1`
   reveal nothing.

Reconstruction reverses this: combine `K` shares to recover the key,
unwrap it with the password if needed, decrypt the ciphertext, and verify
the SHA-256 checksum.

### Why Shamir needs a "finite field"

Polynomial maths only stays exact (no rounding) inside a finite field.
SecureVault uses **GF(2^8)** — the same field AES uses — so every value
fits in a single byte. See `src-tauri/src/core/gf256.rs`.

---

## Project structure

```
secure-vault/
├── package.json            Frontend dependencies + npm scripts
├── vite.config.js          Dev-server / build config for the frontend
├── .gitignore / .dockerignore
│
├── src/                    THE FRONTEND (served by Tauri)
│   ├── index.html          Markup: the four tabs
│   ├── styles.css          The cyber/terminal visual theme
│   └── main.js             UI logic — calls Rust via `invoke()`
│
├── src-tauri/              THE RUST BACKEND
│   ├── Cargo.toml          Rust dependencies
│   ├── build.rs            Tauri build script
│   ├── tauri.conf.json     Main Tauri configuration
│   ├── capabilities/       Permissions the frontend is granted
│   ├── icons/              App icons
│   └── src/
│       ├── main.rs         Binary entry point (a tiny shim)
│       ├── lib.rs          App setup + command registration
│       ├── state.rs        Shared application state
│       │
│       ├── core/           UI-FREE LOGIC (all unit-tested)
│       │   ├── mod.rs
│       │   ├── error.rs        Shared CoreError type
│       │   ├── gf256.rs        Galois Field GF(2^8) arithmetic
│       │   ├── shamir.rs       Shamir's Secret Sharing
│       │   ├── crypto.rs       AES-256-GCM + PBKDF2
│       │   ├── model.rs        Data structures (Fragment, Manifest...)
│       │   ├── fragmenter.rs   Split / reconstruct orchestration
│       │   ├── storage.rs      The secret vault folder
│       │   └── sharing.rs      ZIP packaging of shared fragments
│       │
│       └── commands/       TAURI COMMAND LAYER (thin wrappers)
│           ├── mod.rs
│           ├── dto.rs          Request/response structs
│           ├── vault.rs        split / list / download / delete
│           └── sharing.rs      share / import
│
└── docker/
    ├── Dockerfile          Build + test environment
    └── docker-compose.yml  `test`, `dev`, and `lint` services
```

The **core / commands** split is deliberate: `core` is plain Rust with no
Tauri dependency, so it can be unit-tested with `cargo test` without ever
opening a window. The `commands` layer just translates between the
frontend and `core`.

---

## Prerequisites

To build and run on **Windows** you need:

| Tool | Why | Where |
|------|-----|-------|
| **Rust** (stable, 1.77+) | the backend | <https://rustup.rs> |
| **Node.js** (18+) | frontend tooling | <https://nodejs.org> |
| **Microsoft C++ Build Tools** | Rust links against MSVC | "Desktop development with C++" workload in the Visual Studio Installer |
| **WebView2 runtime** | Tauri's webview | pre-installed on Windows 10/11; otherwise from Microsoft |

For Docker-based development you only need **Docker Desktop**.

---

## Running the app (Windows)

```powershell
# 1. Install frontend dependencies (one time)
npm install

# 2. Start the app in development mode (hot-reloads on changes)
npm run tauri dev
```

`npm run tauri dev` compiles the Rust backend, starts the Vite dev server
for the frontend, and opens the SecureVault window.

The first compile downloads and builds every Rust dependency, so it can
take several minutes. Later builds are fast.

---

## Building a Windows installer

```powershell
npm run tauri build
```

This produces, under `src-tauri/target/release/bundle/`:

* an **`.msi`** installer (`msi/`), and
* an **`.exe`** NSIS installer (`nsis/`).

Either one installs SecureVault as a normal Windows application.

> The placeholder icons in `src-tauri/icons/` are plain coloured squares.
> Replace them with a real icon at any time:
> `npm run tauri icon path\to\your-icon.png`

---

## Development and testing with Docker

A Tauri app draws a **graphical window**, and GUI apps do not run well
inside a plain container. So Docker here is used for what it is good at:
**compiling the backend and running the test suite** in a reproducible
environment. The actual Windows app is still built natively on Windows.

All commands are run from the project root.

```bash
# Run the Rust unit tests (crypto, Shamir, storage, sharing)
docker compose -f docker/docker-compose.yml run --rm test

# Open an interactive shell inside the build environment
docker compose -f docker/docker-compose.yml run --rm dev

# Check formatting and run the clippy linter
docker compose -f docker/docker-compose.yml run --rm lint
```

The compose file defines named volumes that cache Cargo's downloaded
crates, so repeated runs are fast.

### Running the tests natively instead

If you have Rust installed you do not need Docker for tests:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

Every module in `core/` ships with unit tests — for example
`shamir.rs` verifies that any `K` of `N` shares reconstruct the secret
and that `K-1` do not.

---

## The backend command API

The frontend talks to Rust through Tauri's `invoke()`. The seven
registered commands (see `src-tauri/src/lib.rs`):

| Command | Purpose |
|---------|---------|
| `split_and_store` | Encrypt + split a chosen file into the vault. |
| `list_vault_files` | Return every file stored in the vault. |
| `download_vault_file` | Reconstruct a file into the Downloads folder. |
| `delete_vault_file` | Remove a file (all fragments) from the vault. |
| `share_vault_file` | Export the minimum `K` fragments as a `.zip`. |
| `inspect_shared_file` | Read a share `.zip`'s details without importing. |
| `import_shared_file` | Rebuild a shared file and store it in the vault. |

Example call from `main.js`:

```js
import { invoke } from "@tauri-apps/api/core";

const result = await invoke("split_and_store", {
  request: {
    filePath: "C:/Users/me/secret.pdf",
    totalFragments: 5,
    threshold: 3,
    password: null,
  },
});
```

---

## Security notes and limitations

This is a **learning project**. It implements the cryptography correctly,
but a few honest caveats:

* **The "secret folder" cannot be made truly unopenable.** Any folder on
  the user's own machine is reachable by the OS file explorer. SecureVault
  instead **encrypts every file it writes into the vault** (encryption at
  rest) using a machine-local app secret. The user can *locate* the
  folder, but the `.enc` files are unreadable noise without the app. This
  is the honest, real-world way to protect local data.

* **The machine-local app secret** lives in the app-data directory. It
  protects against casual inspection, not against an attacker with full
  control of the machine — that is a fundamentally hard problem and out of
  scope here.

* **Whole files are held in memory** during split/reconstruct. This is
  fine for documents and images; very large files (multi-GB) would need a
  streaming redesign.

* **The crypto crates** (`aes-gcm`, `pbkdf2`, `sha2`, `rand`) are
  well-regarded open-source implementations from the Rust Crypto project,
  but this project has not had a professional security audit.

For a classroom assignment these trade-offs are reasonable and are
documented here so they are visible rather than hidden.

---

## Licence

Provided as-is for educational purposes.
