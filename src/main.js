// SecureVault frontend
// Handles the UI and calls the Rust backend through tauri's invoke()

import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// --- helpers ---

function nowTime() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((x) => String(x).padStart(2, "0"))
    .join(":");
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}

function logTo(consoleId, msg, type = "info") {
  const c = document.getElementById(consoleId);
  if (!c) return;
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML =
    `<span class="log-time">${nowTime()}</span>` +
    `<span class="log-msg ${type}">${msg}</span>`;
  c.appendChild(line);
  c.scrollTop = c.scrollHeight;
}

function toast(msg, type = "ok") {
  const stack = document.getElementById("toastStack");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

// --- tab switching ---

function switchTab(tabName) {
  document.querySelectorAll(".tab").forEach((el) => {
    el.classList.toggle("active", el.dataset.tab === tabName);
  });
  document.querySelectorAll(".panel").forEach((el) => {
    el.classList.remove("active");
  });
  document.getElementById("panel-" + tabName).classList.add("active");

  if (tabName === "vault") refreshVault();
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
document.querySelectorAll("[data-goto]").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.goto));
});

// --- password modal ---
// returns the password string or null if cancelled

function askPassword(title, subtitle) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("passwordModal");
    const input = document.getElementById("modalPasswordInput");
    document.getElementById("modalTitle").textContent = title;
    document.getElementById("modalSub").textContent = subtitle;
    input.value = "";
    overlay.classList.remove("hidden");
    input.focus();

    const cleanup = () => {
      overlay.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onConfirm = () => { cleanup(); resolve(input.value); };
    const onCancel = () => { cleanup(); resolve(null); };

    const confirmBtn = document.getElementById("modalConfirm");
    const cancelBtn = document.getElementById("modalCancel");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

// --- threshold visualisation ---

function updateThresholdVisual() {
  const n = parseInt(document.getElementById("totalShares").value) || 5;
  const k = parseInt(document.getElementById("threshold").value) || 3;
  const container = document.getElementById("thresholdVisual");
  let html = "";
  for (let i = 1; i <= n; i++) {
    html += `<div class="th-dot ${i <= k ? "required" : "extra"}">${i}</div>`;
  }
  container.innerHTML = html;
}

document.getElementById("totalShares").addEventListener("input", () => {
  const n = parseInt(document.getElementById("totalShares").value) || 5;
  const kEl = document.getElementById("threshold");
  kEl.max = n;
  if (parseInt(kEl.value) > n) kEl.value = n;
  updateThresholdVisual();
});
document.getElementById("threshold").addEventListener("input", updateThresholdVisual);

// --- split tab ---

let splitFilePath = null;

document.getElementById("splitDropZone").addEventListener("click", async () => {
  const selected = await open({
    multiple: false,
    directory: false,
    title: "Choose a file to add to the vault",
  });
  if (!selected) return;

  splitFilePath = selected;
  const name = selected.split(/[\\/]/).pop();
  const pill = document.getElementById("splitPickedFile");
  pill.textContent = "📄 " + name;
  pill.classList.remove("hidden");
  document.getElementById("splitDropContent").style.opacity = "0.4";
  logTo("splitConsole", `File selected: ${name}`, "ok");
});

document.getElementById("btnSplit").addEventListener("click", async () => {
  if (!splitFilePath) {
    logTo("splitConsole", "⚠ No file selected", "warn");
    toast("Select a file first", "err");
    return;
  }

  const n = parseInt(document.getElementById("totalShares").value);
  const k = parseInt(document.getElementById("threshold").value);
  const password = document.getElementById("splitPassword").value;

  if (k < 2 || n < 2 || k > n) {
    logTo("splitConsole", "⚠ Invalid parameters: K must be ≥ 2 and ≤ N", "warn");
    return;
  }

  const btn = document.getElementById("btnSplit");
  btn.disabled = true;

  const prog = document.getElementById("splitProgress");
  const bar = document.getElementById("splitProgressBar");
  const lbl = document.getElementById("splitProgressLabel");
  prog.classList.remove("hidden");
  lbl.classList.remove("hidden");
  bar.style.width = "40%";
  lbl.textContent = "Encrypting and splitting…";
  logTo("splitConsole", `Splitting file: N=${n}, K=${k}`, "info");

  try {
    const result = await invoke("split_and_store", {
      request: {
        filePath: splitFilePath,
        totalFragments: n,
        threshold: k,
        password: password || null,
      },
    });
    bar.style.width = "100%";
    lbl.textContent = "Done!";
    logTo("splitConsole", "✓ " + result.message, "ok");
    toast("File added to your vault", "ok");
    resetSplit();
    refreshVault();
  } catch (err) {
    logTo("splitConsole", "✗ Error: " + err, "err");
    toast("Could not add file: " + err, "err");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btnSplitReset").addEventListener("click", resetSplit);

function resetSplit() {
  splitFilePath = null;
  document.getElementById("splitPickedFile").classList.add("hidden");
  document.getElementById("splitDropContent").style.opacity = "1";
  document.getElementById("splitPassword").value = "";
  document.getElementById("splitProgress").classList.add("hidden");
  document.getElementById("splitProgressLabel").classList.add("hidden");
  document.getElementById("splitProgressBar").style.width = "0%";
}

// --- vault tab ---

async function refreshVault() {
  const list = document.getElementById("vaultList");
  list.innerHTML = "";

  let files;
  try {
    files = await invoke("list_vault_files");
  } catch (err) {
    toast("Could not load vault: " + err, "err");
    return;
  }

  if (files.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🗄️</div>
        <div class="empty-state-text">No files in your vault yet.<br>Use "Add File" to get started.</div>
      </div>`;
    return;
  }

  for (const file of files) {
    const item = document.createElement("div");
    item.className = "vault-item";

    const lock = file.passwordProtected
      ? `<span class="lock-badge">🔒 LOCKED</span>` : "";

    item.innerHTML = `
      <div class="vault-item-icon">📄</div>
      <div class="vault-item-body">
        <div class="vault-item-name">${file.filename}${lock}</div>
        <div class="vault-item-meta">
          ${fmtBytes(file.size)} · ${file.totalFragments} fragments ·
          threshold ${file.threshold}
        </div>
      </div>
      <div class="vault-item-actions">
        <button class="icon-btn" title="Download" data-action="download">⬇</button>
        <button class="icon-btn" title="Share" data-action="share">📤</button>
        <button class="icon-btn danger" title="Delete" data-action="delete">🗑</button>
      </div>`;

    item.querySelector('[data-action="download"]')
      .addEventListener("click", (e) => { e.stopPropagation(); downloadFile(file); });
    item.querySelector('[data-action="share"]')
      .addEventListener("click", (e) => { e.stopPropagation(); shareFile(file); });
    item.querySelector('[data-action="delete"]')
      .addEventListener("click", (e) => { e.stopPropagation(); deleteFile(file); });
    item.addEventListener("click", () => downloadFile(file));

    list.appendChild(item);
  }
}

async function downloadFile(file) {
  let password = null;
  if (file.passwordProtected) {
    password = await askPassword(
      "Password Required",
      `"${file.filename}" is password protected.`
    );
    if (password === null) return;
  }

  try {
    const result = await invoke("download_vault_file", {
      fileId: file.fileId,
      password: password,
    });
    toast(result.message, "ok");
  } catch (err) {
    toast("Download failed: " + err, "err");
  }
}

async function shareFile(file) {
  try {
    const result = await invoke("share_vault_file", { fileId: file.fileId });
    toast(result.message, "ok");
  } catch (err) {
    toast("Share failed: " + err, "err");
  }
}

async function deleteFile(file) {
  if (!window.confirm(`Delete "${file.filename}" from the vault? This cannot be undone.`))
    return;

  try {
    await invoke("delete_vault_file", { fileId: file.fileId });
    toast("File removed from the vault", "ok");
    refreshVault();
  } catch (err) {
    toast("Delete failed: " + err, "err");
  }
}

document.getElementById("btnRefreshVault").addEventListener("click", refreshVault);

// --- import tab ---

let importZipPath = null;
let importInfo = null;

document.getElementById("importDropZone").addEventListener("click", async () => {
  const selected = await open({
    multiple: false,
    directory: false,
    title: "Choose a shared .zip bundle",
    filters: [{ name: "SecureVault Share", extensions: ["zip"] }],
  });
  if (!selected) return;

  importZipPath = selected;
  const name = selected.split(/[\\/]/).pop();
  const pill = document.getElementById("importPickedFile");
  pill.textContent = "📦 " + name;
  pill.classList.remove("hidden");
  document.getElementById("importDropContent").style.opacity = "0.4";
  logTo("importConsole", `Bundle selected: ${name}`, "ok");

  // inspect the bundle to see if it needs a password
  try {
    importInfo = await invoke("inspect_shared_file", { zipPath: importZipPath });
    const lock = importInfo.passwordProtected ? " · 🔒 password protected" : "";
    document.getElementById("importInfo").textContent =
      `${importInfo.filename} · ${fmtBytes(importInfo.size)} · ` +
      `${importInfo.fragmentCount} fragments · threshold ${importInfo.threshold}${lock}`;
    document.getElementById("importInfoCard").classList.remove("hidden");
    logTo("importConsole", "✓ Bundle inspected successfully", "ok");
  } catch (err) {
    logTo("importConsole", "✗ Could not read bundle: " + err, "err");
    toast("Invalid share bundle", "err");
  }
});

document.getElementById("btnImport").addEventListener("click", async () => {
  if (!importZipPath) {
    logTo("importConsole", "⚠ No bundle selected", "warn");
    return;
  }

  let password = null;
  if (importInfo && importInfo.passwordProtected) {
    password = await askPassword(
      "Password Required",
      `"${importInfo.filename}" requires a password to reconstruct.`
    );
    if (password === null) return;
  }

  const btn = document.getElementById("btnImport");
  btn.disabled = true;
  logTo("importConsole", "Importing and re-fragmenting…", "info");

  try {
    const result = await invoke("import_shared_file", {
      zipPath: importZipPath,
      password: password,
    });
    logTo("importConsole", "✓ " + result.message, "ok");
    toast("File imported into your vault", "ok");
    resetImport();
    refreshVault();
  } catch (err) {
    logTo("importConsole", "✗ Error: " + err, "err");
    toast("Import failed: " + err, "err");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btnImportReset").addEventListener("click", resetImport);

function resetImport() {
  importZipPath = null;
  importInfo = null;
  document.getElementById("importPickedFile").classList.add("hidden");
  document.getElementById("importDropContent").style.opacity = "1";
  document.getElementById("importInfoCard").classList.add("hidden");
}

// --- init ---

updateThresholdVisual();
refreshVault();
