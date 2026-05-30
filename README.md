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

1. **Encrypt the file.** A random 256-bit key is generated and the entire
   file is encrypted once with **AES-256-GCM**. 

2. **Split only the key.** The small 32-byte AES key is the secret that
   gets **Shamir-split** into `N` shares.

3. **Optional password layer.** If the user sets a password, the AES key
   is itself encrypted *before* being split.

4. **Package fragments.** Each fragment is formatted to `.svf`. Any `K` fragments rebuild the file; any `K-1`
   reveal nothing.

Reconstruction reverses this.

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

Both `npm install` and `npm run tauri dev` require **Rust** to be installed.
`npm install` only downloads JavaScript packages and will succeed on its own,
but `npm run tauri dev` compiles the entire Rust backend using `cargo` — so
without Rust installed it will fail immediately.

### 1. Install Rust

Download and run the installer from <https://rustup.rs>. This installs
`rustc` (the compiler) and `cargo` (the package manager). Choose the
default options when prompted.

After installation, **restart your terminal** so that `cargo` is available
on your PATH. Verify with:

```powershell
rustc --version
cargo --version
```

### 2. Install Microsoft C++ Build Tools

Rust on Windows compiles native code using MSVC. You need the
**"Desktop development with C++"** workload from the Visual Studio
Installer:

<https://visualstudio.microsoft.com/visual-cpp-build-tools/>

Download the Build Tools installer, run it, tick "Desktop development
with C++", and install. This can take a few minutes.

### 3. Install Node.js

Download and install Node.js (version 18 or later) from
<https://nodejs.org>. The LTS version is recommended. Verify with:

```powershell
rustup update
rustc --version

node --version
npm --version
```

### 4. WebView2 Runtime

Tauri uses the system WebView2 runtime to render the frontend. This is
**pre-installed on Windows 10 and 11**, so you most likely already have it.
If not, download it from Microsoft:
<https://developer.microsoft.com/en-us/microsoft-edge/webview2/>

### 5. Docker (optional)

For Docker-based development and testing you need **Docker Desktop**.
This is not required to build or run the app — it is only used for
running the test suite and linter in a container.

### Troubleshooting: PowerShell execution policy

If PowerShell blocks scripts with an error like
*"running scripts is disabled on this system"*, you need to allow script
execution. Open PowerShell and run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

You only need to do this once.

---

## Running the app (Windows Live Testing)

Make sure Rust, Node.js, and the C++ Build Tools are all installed
(see [Prerequisites](#prerequisites) above) before continuing.

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

## Building a Windows installer(Optional)

```powershell
npm run tauri build
```

This produces, under `src-tauri/target/release/bundle/`:

* an **`.msi`** installer (`msi/`), and
* an **`.exe`** NSIS installer (`nsis/`).

Either one installs SecureVault as a normal Windows application.


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

