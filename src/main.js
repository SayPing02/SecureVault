// SecureVault frontend
// Handles the UI and calls the Rust backend through tauri's invoke()

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { getCurrentWebview } from "@tauri-apps/api/webview";

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
  if (n < 1073741824) return (n / 1048576).toFixed(2) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

// createdAt is unix seconds from the backend
function fmtDate(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleDateString(undefined, {
    day: "numeric", month: "short", year: "numeric",
  });
}

// Date + time, for the activity log (fmtDate alone doesn't distinguish
// same-day entries).
function fmtDateTime(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  const date = d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `${date}, ${time}`;
}

// Rough time estimate: AES enc ~100 MB/s + writing N encrypted copies at ~100 MB/s
function estimateSplitMs(sizeBytes, totalFragments) {
  const mb = sizeBytes / (1024 * 1024);
  const encMs = (mb / 100) * 1000;
  const writeMs = (mb * totalFragments / 100) * 1000;
  return Math.max(300, Math.round(encMs + writeMs));
}

// Rotation is considered stale past this many days — just a nudge, not
// enforced (see the in-app discussion: offline expiry can't be enforced by
// a local clock, so this is a reminder, never a block).
const ROTATION_STALE_DAYS = 180;

function fmtRotationAge(unixSeconds) {
  const days = Math.floor((Date.now() / 1000 - unixSeconds) / 86400);
  if (days < 1) return "today";
  if (days < 31) return `${days} day${days === 1 ? "" : "s"} ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
  const years = Math.floor(months / 12);
  return `${years} year${years === 1 ? "" : "s"} ago`;
}

function fmtDuration(ms) {
  if (ms < 1000) return "< 1 sec";
  const s = Math.round(ms / 1000);
  if (s < 60) return `~${s} sec`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `~${m}m ${rem > 0 ? rem + "s" : ""}`.trim();
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

// Matches the Display string of Rust's CoreError::Cancelled — used to tell
// a user-initiated cancel apart from a real failure in a catch block.
const CANCELLED_MSG = "operation cancelled";
function isCancelled(err) {
  return String(err) === CANCELLED_MSG;
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
  if (tabName === "settings") refreshSecurityStatus();
  if (tabName === "activity") refreshActivityLog();
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
document.querySelectorAll("[data-goto]").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.goto));
});

// --- password modal ---

// If verifyFn is given, Confirm checks the password before closing the modal:
// wrong password shows an inline error and lets the user retry immediately,
// instead of closing the modal and only failing later once the full
// download/reconstruction is already under way.
function askPassword(title, subtitle, verifyFn) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("passwordModal");
    const input = document.getElementById("modalPasswordInput");
    const errorEl = document.getElementById("modalError");
    document.getElementById("modalTitle").textContent = title;
    document.getElementById("modalSub").textContent = subtitle;
    input.value = "";
    errorEl.classList.add("hidden");
    overlay.classList.remove("hidden");
    input.focus();

    const cleanup = () => {
      overlay.classList.add("hidden");
      errorEl.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onCancel = () => { cleanup(); resolve(null); };

    const onConfirm = async () => {
      const pw = input.value;
      if (!verifyFn) { cleanup(); resolve(pw); return; }

      errorEl.classList.add("hidden");
      confirmBtn.disabled = true;
      confirmBtn.textContent = "Checking…";
      try {
        const ok = await verifyFn(pw);
        if (ok) {
          cleanup();
          resolve(pw);
          return;
        }
        errorEl.textContent = "Incorrect password";
        errorEl.classList.remove("hidden");
        input.select();
      } catch (err) {
        errorEl.textContent = String(err);
        errorEl.classList.remove("hidden");
      } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = "Confirm";
      }
    };

    const confirmBtn = document.getElementById("modalConfirm");
    const cancelBtn = document.getElementById("modalCancel");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

// --- share zip name modal ---

// Lets the user rename the exported share zip before it's written.
// Resolves the chosen name, or null if cancelled. Leaving it blank/unchanged
// keeps the app's default "<file>-share.zip" name (the backend fills that in
// if an empty string is sent).
function askZipName(defaultName) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("zipNameModal");
    const input = document.getElementById("zipNameInput");
    document.getElementById("zipNameModalSub").textContent =
      `Default: ${defaultName}`;
    input.value = defaultName.replace(/\.zip$/i, "");
    overlay.classList.remove("hidden");
    input.focus();
    input.select();

    const cleanup = () => {
      overlay.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onCancel = () => { cleanup(); resolve(null); };
    const onConfirm = () => { cleanup(); resolve(input.value.trim()); };

    const confirmBtn = document.getElementById("zipNameConfirm");
    const cancelBtn = document.getElementById("zipNameCancel");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

// --- fragment recommendation based on file size ---

function recommendFragments(bytes) {
  const MB = 1024 * 1024;
  const GB = 1024 * MB;
  if (bytes < 1 * MB)   return { n: 3,  k: 2, label: "Tiny file (<1 MB)"       };
  if (bytes < 10 * MB)  return { n: 5,  k: 3, label: "Small file (<10 MB)"     };
  if (bytes < 100 * MB) return { n: 5,  k: 3, label: "Medium file (<100 MB)"   };
  if (bytes < 1 * GB)   return { n: 7,  k: 4, label: "Large file (<1 GB)"      };
  if (bytes < 10 * GB)  return { n: 8,  k: 5, label: "Very large file (<10 GB)"};
  return                       { n: 10, k: 6, label: "Huge file (10 GB+)"       };
}

function showRecommendBanner(bytes) {
  const rec = recommendFragments(bytes);
  const banner = document.getElementById("splitRecommendBanner");
  document.getElementById("splitRecommendText").textContent =
    `${rec.label} — recommended ${rec.k}-of-${rec.n} (threshold ${rec.k}, total ${rec.n})`;
  banner.dataset.n = rec.n;
  banner.dataset.k = rec.k;
  banner.classList.remove("hidden");
}

document.getElementById("btnRecommendApply").addEventListener("click", () => {
  const banner = document.getElementById("splitRecommendBanner");
  document.getElementById("totalShares").value = banner.dataset.n;
  document.getElementById("threshold").value = banner.dataset.k;
  updateThresholdVisual();
  updateSplitEstimate();
  banner.classList.add("hidden");
});

document.getElementById("btnRecommendDismiss").addEventListener("click", () => {
  document.getElementById("splitRecommendBanner").classList.add("hidden");
});

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
  // threshold must be < total (Reed-Solomon needs at least 1 parity shard)
  if (parseInt(kEl.value) >= n) kEl.value = Math.max(2, n - 1);
  updateThresholdVisual();
  updateSplitEstimate();
});
document.getElementById("splitCompress").addEventListener("change", updateSplitEstimate);
document.getElementById("threshold").addEventListener("input", () => {
  const n = parseInt(document.getElementById("totalShares").value) || 5;
  const kEl = document.getElementById("threshold");
  // clamp threshold to n-1 so there is always at least 1 parity shard
  if (parseInt(kEl.value) >= n) kEl.value = Math.max(2, n - 1);
  updateThresholdVisual();
});

// Cipher selection: collapsed recommendation row by default, full card grid
// only once the user asks to "Change" it. See applyCipherChoice() below.
let lastRecommendedCipher = "aes256gcm";

async function showCipherRecommendation(fileSize) {
  try {
    const rec = await invoke("recommend_cipher", { fileSize });
    lastRecommendedCipher = rec.cipher;
    applyCipherChoice(rec.cipher, rec.reason);
  } catch (err) {
    // Non-critical — leave whichever cipher is already selected.
  }
}

function applyCipherChoice(cipherValue, reasonText) {
  document.querySelectorAll(".cipher-card").forEach((c) => c.classList.remove("selected"));
  const card = document.querySelector(`.cipher-card[data-value="${cipherValue}"]`);
  if (card) {
    card.classList.add("selected");
    card.querySelector("input[type=radio]").checked = true;
  }

  const isRecommended = cipherValue === lastRecommendedCipher;
  document.getElementById("cipherCollapsedName").textContent =
    card ? card.querySelector(".cipher-name").textContent : cipherValue;
  document.getElementById("cipherCollapsedReason").textContent =
    reasonText ?? (card ? card.querySelector(".cipher-desc").textContent : "");
  document.querySelector("#cipherCollapsed .cipher-badge").textContent =
    isRecommended ? "Recommended" : "Selected";

  document.getElementById("cipherCollapsed").classList.remove("hidden");
  document.getElementById("cipherGrid").classList.add("hidden");
}

document.getElementById("cipherChangeBtn").addEventListener("click", () => {
  document.getElementById("cipherCollapsed").classList.add("hidden");
  document.getElementById("cipherGrid").classList.remove("hidden");
});

document.querySelectorAll(".cipher-card").forEach((card) => {
  card.addEventListener("click", () => {
    applyCipherChoice(card.dataset.value, null);
  });
});

// KDF card selection (scoped to #kdfGrid so it doesn't interfere with padding grid)
document.querySelectorAll("#kdfGrid .kdf-card").forEach((card) => {
  card.addEventListener("click", () => {
    document.querySelectorAll("#kdfGrid .kdf-card").forEach((c) => c.classList.remove("selected"));
    card.classList.add("selected");
    card.querySelector("input[type=radio]").checked = true;
  });
});

// Padding card selection
document.querySelectorAll("#paddingGrid .kdf-card").forEach((card) => {
  card.addEventListener("click", () => {
    document.querySelectorAll("#paddingGrid .kdf-card").forEach((c) => c.classList.remove("selected"));
    card.classList.add("selected");
    card.querySelector("input[type=radio]").checked = true;
  });
});

function getSelectedCipher() {
  return document.querySelector('input[name="cipher"]:checked')?.value ?? "aes256gcm";
}

function getSelectedKdf() {
  return document.querySelector('input[name="kdf"]:checked')?.value ?? "standard";
}

function getSelectedPadding() {
  return parseInt(document.querySelector('input[name="padding"]:checked')?.value ?? "0");
}

// --- split tab ---

let splitFilePath = null;
let splitFileSize = 0;
let unlistenProgress = null;

const MIN_PASSWORD_LENGTH = 8;

function updatePasswordHint() {
  const pw = document.getElementById("splitPassword").value;
  const hint = document.getElementById("splitPasswordHint");
  if (pw.length === 0) {
    hint.textContent = "";
    hint.className = "password-hint";
  } else if (pw.length < MIN_PASSWORD_LENGTH) {
    hint.textContent = `Need at least ${MIN_PASSWORD_LENGTH} characters (${pw.length}/${MIN_PASSWORD_LENGTH})`;
    hint.className = "password-hint warn";
  } else {
    hint.textContent = "Password length OK";
    hint.className = "password-hint ok";
  }

  document.getElementById("kdfSection").classList.toggle("hidden", pw.length === 0);
}

document.getElementById("splitPassword").addEventListener("input", updatePasswordHint);

async function updateSplitEstimate() {
  if (!splitFilePath || splitFileSize <= 0) return;
  const n = parseInt(document.getElementById("totalShares").value) || 5;
  const compress = document.getElementById("splitCompress").checked;
  // Compressed files are roughly 40% of original for typical documents
  const effectiveSize = compress ? splitFileSize * 0.4 : splitFileSize;
  const estimatedMs = estimateSplitMs(effectiveSize, n);
  const vaultBytes = effectiveSize * 1.37 * n;

  document.getElementById("splitFileSizeDisplay").textContent =
    `File: ${fmtBytes(splitFileSize)}`;
  document.getElementById("splitVaultSpaceDisplay").textContent =
    `Vault: ~${fmtBytes(vaultBytes)}`;
  document.getElementById("splitTimeEstDisplay").textContent =
    `Est. ${fmtDuration(estimatedMs)}`;

  const infoBar = document.getElementById("splitFileInfoBar");
  infoBar.classList.remove("hidden");

  const warning = document.getElementById("splitLargeFileWarning");
  // Show warning when vault usage will exceed 500 MB
  if (vaultBytes > 500 * 1024 * 1024) {
    warning.textContent =
      `Large file: each of the ${n} fragments stores a full encrypted copy ` +
      `(~${fmtBytes(vaultBytes)} total vault space needed).`;
    warning.classList.remove("hidden");
  } else {
    warning.classList.add("hidden");
  }
}

function showFileNameRow(name) {
  document.getElementById("splitFileNameInput").value = name;
  document.getElementById("splitFileNameRow").classList.remove("hidden");
}

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
  pill.textContent = name;
  pill.classList.remove("hidden");
  showFileNameRow(name);
  document.getElementById("splitDropContent").style.opacity = "0.4";
  logTo("splitConsole", `File selected: ${name}`, "ok");

  try {
    splitFileSize = await invoke("get_file_size", { filePath: splitFilePath });
    await updateSplitEstimate();
    showRecommendBanner(splitFileSize);
    await showCipherRecommendation(splitFileSize);
    logTo("splitConsole", `Size: ${fmtBytes(splitFileSize)}`, "info");
  } catch (err) {
    logTo("splitConsole", `Could not read file size: ${err}`, "warn");
  }
});

document.getElementById("btnSplit").addEventListener("click", async () => {
  if (!splitFilePath) {
    logTo("splitConsole", "No file selected", "warn");
    toast("Select a file first", "err");
    return;
  }

  const n = parseInt(document.getElementById("totalShares").value);
  const k = parseInt(document.getElementById("threshold").value);
  const password = document.getElementById("splitPassword").value;
  const compress = document.getElementById("splitCompress").checked;
  const filename = document.getElementById("splitFileNameInput").value.trim();

  if (!filename) {
    logTo("splitConsole", "File name cannot be empty", "warn");
    toast("Enter a name to store the file under", "err");
    return;
  }

  if (k < 2 || n < 2 || k > n) {
    logTo("splitConsole", "Invalid parameters: K must be ≥ 2 and ≤ N", "warn");
    return;
  }

  if (password.length > 0 && password.length < MIN_PASSWORD_LENGTH) {
    logTo("splitConsole", `Password must be at least ${MIN_PASSWORD_LENGTH} characters`, "warn");
    toast(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`, "err");
    return;
  }

  const btn = document.getElementById("btnSplit");
  btn.disabled = true;

  const prog = document.getElementById("splitProgress");
  const bar = document.getElementById("splitProgressBar");
  const footer = document.getElementById("splitProgressFooter");
  const lbl = document.getElementById("splitProgressLabel");
  const timeEl = document.getElementById("splitTimeRemaining");

  prog.classList.remove("hidden");
  footer.classList.remove("hidden");
  bar.style.width = "5%";
  lbl.textContent = "Starting…";
  timeEl.textContent = "";
  logTo("splitConsole", `Splitting file: N=${n}, K=${k}${compress ? " · compression ON" : ""}`, "info");

  const startMs = Date.now();
  const operationId = crypto.randomUUID();
  const pauseBtn = document.getElementById("btnSplitPause");
  const cancelBtn = document.getElementById("btnSplitCancel");
  let paused = false;

  pauseBtn.classList.remove("hidden");
  cancelBtn.classList.remove("hidden");
  pauseBtn.disabled = false;
  cancelBtn.disabled = false;
  pauseBtn.textContent = "Pause";

  pauseBtn.onclick = async () => {
    paused = !paused;
    await invoke(paused ? "pause_operation" : "resume_operation", { operationId });
    pauseBtn.textContent = paused ? "Resume" : "Pause";
  };
  cancelBtn.onclick = async () => {
    cancelBtn.disabled = true;
    await invoke("cancel_operation", { operationId });
  };

  // Subscribe to progress events from the Rust backend
  unlistenProgress = await listen("split-progress", ({ payload }) => {
    const { percent, message } = payload;
    bar.style.width = percent + "%";
    lbl.textContent = message;

    if (percent > 5 && percent < 100) {
      const elapsed = Date.now() - startMs;
      const totalEstimated = elapsed / (percent / 100);
      const remaining = Math.max(0, totalEstimated - elapsed);
      timeEl.textContent = fmtDuration(remaining) + " remaining";
    } else if (percent === 100) {
      timeEl.textContent = `Done in ${fmtDuration(Date.now() - startMs)}`;
    }
  });

  try {
    const result = await invoke("split_and_store", {
      request: {
        filePath: splitFilePath,
        filename,
        totalFragments: n,
        threshold: k,
        password: password || null,
        compress,
        cipher: getSelectedCipher(),
        kdf: getSelectedKdf(),
        paddingPct: getSelectedPadding(),
      },
      operationId,
    });
    bar.style.width = "100%";
    lbl.textContent = "Done!";
    logTo("splitConsole", result.message, "ok");
    toast("File added to your vault", "ok");
    resetSplit();
    refreshVault();
  } catch (err) {
    if (isCancelled(err)) {
      logTo("splitConsole", "Cancelled", "info");
      toast("Split cancelled", "ok");
      lbl.textContent = "Cancelled";
    } else {
      logTo("splitConsole", "Error: " + err, "err");
      toast("Could not add file: " + err, "err");
      lbl.textContent = "Failed";
    }
    timeEl.textContent = "";
  } finally {
    btn.disabled = false;
    pauseBtn.classList.add("hidden");
    cancelBtn.classList.add("hidden");
    if (unlistenProgress) { unlistenProgress(); unlistenProgress = null; }
  }
});

document.getElementById("btnSplitReset").addEventListener("click", resetSplit);

function resetSplit() {
  splitFilePath = null;
  splitFileSize = 0;
  if (unlistenProgress) { unlistenProgress(); unlistenProgress = null; }
  document.getElementById("splitPickedFile").classList.add("hidden");
  document.getElementById("splitFileNameRow").classList.add("hidden");
  document.getElementById("splitFileNameInput").value = "";
  document.getElementById("splitDropContent").style.opacity = "1";
  document.getElementById("splitPassword").value = "";
  updatePasswordHint();
  document.getElementById("splitProgress").classList.add("hidden");
  document.getElementById("splitProgressFooter").classList.add("hidden");
  document.getElementById("splitProgressBar").style.width = "0%";
  document.getElementById("splitProgressLabel").textContent = "";
  document.getElementById("splitTimeRemaining").textContent = "";
  document.getElementById("btnSplitPause").classList.add("hidden");
  document.getElementById("btnSplitCancel").classList.add("hidden");
  document.getElementById("splitFileInfoBar").classList.add("hidden");
  document.getElementById("splitLargeFileWarning").classList.add("hidden");
  document.getElementById("splitRecommendBanner").classList.add("hidden");
  lastRecommendedCipher = "aes256gcm";
  applyCipherChoice("aes256gcm", "Industry-standard, hardware-accelerated on most devices.");
}

// --- vault tab ---

// Full list from the backend, cached so search can filter client-side
// without re-fetching on every keystroke.
let vaultFiles = [];

async function refreshVault() {
  const list = document.getElementById("vaultList");
  list.innerHTML = `
    <div class="empty-state">
      <div class="empty-state-text">Loading vault…</div>
    </div>`;

  try {
    vaultFiles = await invoke("list_vault_files");
  } catch (err) {
    toast("Could not load vault: " + err, "err");
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-text">Could not load your vault.<br>Try "Refresh" below.</div>
      </div>`;
    return;
  }

  renderVaultList();
}

function renderVaultList() {
  const list = document.getElementById("vaultList");

  if (vaultFiles.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-text">No files in your vault yet.<br>Use "Add File" to get started.</div>
      </div>`;
    return;
  }

  const query = document.getElementById("vaultSearchInput").value.trim().toLowerCase();
  const files = (query
    ? vaultFiles.filter((f) => f.filename.toLowerCase().includes(query))
    : vaultFiles
  ).slice().sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));

  if (files.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-text">No files match "${query}".</div>
      </div>`;
    return;
  }

  list.innerHTML = "";

  for (const file of files) {
    const item = document.createElement("div");
    item.className = "vault-item" + (file.pinned ? " pinned" : "");

    const lock = file.passwordProtected
      ? `<span class="lock-badge">LOCKED</span>` : "";
    const pinnedBadge = file.pinned
      ? `<span class="pinned-badge">PINNED</span>` : "";
    const rotatedAt = file.lastRotatedAt || file.createdAt;
    const isStale = (Date.now() / 1000 - rotatedAt) > ROTATION_STALE_DAYS * 86400;
    const staleBadge = isStale ? `<span class="stale-badge">ROTATE?</span>` : "";
    const ext = (file.filename.split(".").pop() || "file").slice(0, 4).toUpperCase();
    const labelCount = Object.keys(file.fragmentLabels || {}).length;
    const labelsBtnText = labelCount > 0 ? `Labels (${labelCount})` : "Labels";
    const pinBtnText = file.pinned ? "Unpin" : "Pin";

    item.innerHTML = `
      <div class="vault-item-icon">${ext}</div>
      <div class="vault-item-body">
        <div class="vault-item-name">
          <span class="vault-item-filename" title="${file.filename}">${file.filename}</span>${lock}${pinnedBadge}${staleBadge}
        </div>
        <div class="vault-item-meta">
          ${fmtBytes(file.size)} · ${file.totalFragments} fragments ·
          threshold ${file.threshold} · Created ${fmtDate(file.createdAt)} ·
          Rotated ${fmtRotationAge(rotatedAt)}
        </div>
        <div class="vault-item-progress hidden" data-role="progress">
          <div class="progress-wrap">
            <div class="progress-bar" data-role="progress-bar"></div>
          </div>
          <div class="progress-row">
            <div class="progress-label" data-role="progress-label"></div>
            <div class="progress-controls">
              <button class="icon-btn icon-btn-sm" data-role="progress-pause" title="Pause">Pause</button>
              <button class="icon-btn icon-btn-sm danger" data-role="progress-cancel" title="Cancel">Cancel</button>
            </div>
          </div>
        </div>
      </div>
      <div class="vault-item-actions">
        <div class="item-menu">
          <button class="icon-btn item-menu-trigger" title="More actions" data-action="menu">⋯</button>
          <div class="item-menu-dropdown hidden">
            <button class="item-menu-option" data-action="pin">${pinBtnText}</button>
            <button class="item-menu-option" data-action="download">Download</button>
            <button class="item-menu-option" data-action="share">Share</button>
            <button class="item-menu-option" data-action="labels">${labelsBtnText}</button>
            <button class="item-menu-option" data-action="rotate">Rotate Fragments</button>
            <button class="item-menu-option danger" data-action="delete">Delete</button>
          </div>
        </div>
      </div>`;

    const menuBtn = item.querySelector('[data-action="menu"]');
    const dropdown = item.querySelector(".item-menu-dropdown");
    menuBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const wasOpen = !dropdown.classList.contains("hidden");
      closeAllItemMenus();
      if (!wasOpen) {
        dropdown.classList.remove("hidden");
        item.classList.add("menu-open");
      }
    });

    item.querySelector('[data-action="pin"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); toggleFilePinned(file); });
    item.querySelector('[data-action="download"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); downloadFile(file, item); });
    item.querySelector('[data-action="share"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); shareFile(file, item); });
    item.querySelector('[data-action="labels"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); openLabelsModal(file); });
    item.querySelector('[data-action="rotate"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); rotateFile(file); });
    item.querySelector('[data-action="delete"]')
      .addEventListener("click", (e) => { e.stopPropagation(); closeAllItemMenus(); deleteFile(file); });
    item.addEventListener("click", () => openFragmentPreview(file));

    list.appendChild(item);
  }
}

function closeAllItemMenus() {
  document.querySelectorAll(".item-menu-dropdown").forEach((el) => el.classList.add("hidden"));
  document.querySelectorAll(".vault-item.menu-open").forEach((el) => el.classList.remove("menu-open"));
}
document.addEventListener("click", closeAllItemMenus);

async function toggleFilePinned(file) {
  const wantPinned = !file.pinned;
  try {
    await invoke("set_file_pinned", { fileId: file.fileId, pinned: wantPinned });
    file.pinned = wantPinned;
    renderVaultList();
  } catch (err) {
    toast("Could not update pin: " + err, "err");
  }
}

// show/update/hide the mini progress bar embedded in a vault-item row
function showItemProgress(item) {
  const row = item.querySelector('[data-role="progress"]');
  row.classList.remove("hidden");
  return {
    bar: row.querySelector('[data-role="progress-bar"]'),
    label: row.querySelector('[data-role="progress-label"]'),
    pauseBtn: row.querySelector('[data-role="progress-pause"]'),
    cancelBtn: row.querySelector('[data-role="progress-cancel"]'),
  };
}

function hideItemProgress(item) {
  const row = item.querySelector('[data-role="progress"]');
  if (row) row.classList.add("hidden");
}

async function downloadFile(file, item) {
  let password = null;
  if (file.passwordProtected) {
    password = await askPassword(
      "Password Required",
      `"${file.filename}" is password protected.`,
      (pw) => invoke("verify_file_password", { fileId: file.fileId, password: pw })
    );
    if (password === null) return;
  }

  const btn = item.querySelector('[data-action="download"]');
  if (btn) { btn.disabled = true; btn.textContent = "Working…"; }

  const { bar, label, pauseBtn, cancelBtn } = showItemProgress(item);
  bar.style.width = "2%";
  label.textContent = "Starting…";

  const operationId = crypto.randomUUID();
  let paused = false;
  cancelBtn.disabled = false;
  pauseBtn.textContent = "Pause";
  pauseBtn.onclick = async (e) => {
    e.stopPropagation();
    paused = !paused;
    await invoke(paused ? "pause_operation" : "resume_operation", { operationId });
    pauseBtn.textContent = paused ? "Resume" : "Pause";
  };
  cancelBtn.onclick = async (e) => {
    e.stopPropagation();
    cancelBtn.disabled = true;
    await invoke("cancel_operation", { operationId });
  };

  const unlisten = await listen("download-progress", ({ payload }) => {
    bar.style.width = payload.percent + "%";
    label.textContent = payload.message;
  });

  try {
    const result = await invoke("download_vault_file", {
      fileId: file.fileId,
      password: password,
      operationId,
    });
    bar.style.width = "100%";
    label.textContent = "Done";
    toast(result.message, "ok");
    if (result.outputPath) {
      await revealItemInDir(result.outputPath).catch(() => {});
    }
  } catch (err) {
    if (isCancelled(err)) {
      toast("Download cancelled", "ok");
      label.textContent = "Cancelled";
    } else {
      toast("Download failed: " + err, "err");
      label.textContent = "Failed";
    }
  } finally {
    unlisten();
    if (btn) { btn.disabled = false; btn.textContent = "Download"; }
    setTimeout(() => hideItemProgress(item), 1200);
  }
}

async function shareFile(file, item) {
  let password = null;
  if (file.passwordProtected) {
    password = await askPassword(
      "Password Required",
      `"${file.filename}" is password protected. Enter the password to share it.`,
      (pw) => invoke("verify_file_password", { fileId: file.fileId, password: pw })
    );
    if (password === null) return;
  }

  const stem = file.filename.replace(/\.[^./\\]+$/, "");
  const zipName = await askZipName(`${stem}-share.zip`);
  if (zipName === null) return;

  const btn = item.querySelector('[data-action="share"]');
  if (btn) { btn.disabled = true; btn.textContent = "Working…"; }

  const { bar, label, pauseBtn, cancelBtn } = showItemProgress(item);
  bar.style.width = "2%";
  label.textContent = "Starting…";

  const operationId = crypto.randomUUID();
  let paused = false;
  cancelBtn.disabled = false;
  pauseBtn.textContent = "Pause";
  pauseBtn.onclick = async (e) => {
    e.stopPropagation();
    paused = !paused;
    await invoke(paused ? "pause_operation" : "resume_operation", { operationId });
    pauseBtn.textContent = paused ? "Resume" : "Pause";
  };
  cancelBtn.onclick = async (e) => {
    e.stopPropagation();
    cancelBtn.disabled = true;
    await invoke("cancel_operation", { operationId });
  };

  const unlisten = await listen("share-progress", ({ payload }) => {
    bar.style.width = payload.percent + "%";
    label.textContent = payload.message;
  });

  try {
    const result = await invoke("share_vault_file", { fileId: file.fileId, password: password, zipName: zipName, operationId });
    bar.style.width = "100%";
    label.textContent = "Done";
    toast(result.message, "ok");
  } catch (err) {
    if (isCancelled(err)) {
      toast("Share cancelled", "ok");
      label.textContent = "Cancelled";
    } else {
      toast("Share failed: " + err, "err");
      label.textContent = "Failed";
    }
  } finally {
    unlisten();
    if (btn) { btn.disabled = false; btn.textContent = "Share"; }
    setTimeout(() => hideItemProgress(item), 1200);
  }
}

async function rotateFile(file) {
  if (!window.confirm(
    `Rotate "${file.filename}"? This creates a brand-new set of fragments — ` +
    `any old fragments still out there (USB drives, shared copies, etc.) will stop working immediately.`
  )) return;

  try {
    if (file.passwordProtected) {
      const confirmed = await askPassword(
        "Confirm Password",
        `Enter the password for "${file.filename}" to rotate its fragments.`,
        (pw) => invoke("rotate_vault_file", { fileId: file.fileId, password: pw }).then(() => true)
      );
      if (confirmed === null) return;
    } else {
      await invoke("rotate_vault_file", { fileId: file.fileId, password: null });
    }
    toast(`"${file.filename}" rotated — old fragments are now invalid`, "ok");
    refreshVault();
  } catch (err) {
    toast("Rotation failed: " + err, "err");
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

// --- fragment destination labels ---

function openLabelsModal(file) {
  const overlay = document.getElementById("labelsModal");
  const list = document.getElementById("labelsList");
  const existing = file.fragmentLabels || {};

  document.getElementById("labelsModalSub").textContent =
    `"${file.filename}" · ${file.totalFragments} fragments`;

  let html = "";
  for (let i = 1; i <= file.totalFragments; i++) {
    const value = (existing[i] ?? "").replace(/"/g, "&quot;");
    html += `
      <div class="label-row">
        <span class="label-row-num">${i}</span>
        <input type="text" class="label-row-input" data-index="${i}"
               placeholder="e.g. Mom's laptop, USB drive…" value="${value}">
      </div>`;
  }
  list.innerHTML = html;
  overlay.classList.remove("hidden");

  const cleanup = () => {
    overlay.classList.add("hidden");
    saveBtn.removeEventListener("click", onSave);
    cancelBtn.removeEventListener("click", onCancel);
  };
  const onCancel = () => cleanup();

  const onSave = async () => {
    const labels = {};
    list.querySelectorAll(".label-row-input").forEach((input) => {
      if (input.value.trim().length > 0) {
        labels[input.dataset.index] = input.value.trim();
      }
    });

    saveBtn.disabled = true;
    try {
      await invoke("update_fragment_labels", { fileId: file.fileId, labels });
      toast("Fragment labels saved", "ok");
      cleanup();
      refreshVault();
    } catch (err) {
      toast("Could not save labels: " + err, "err");
    } finally {
      saveBtn.disabled = false;
    }
  };

  const saveBtn = document.getElementById("labelsSave");
  const cancelBtn = document.getElementById("labelsCancel");
  saveBtn.addEventListener("click", onSave);
  cancelBtn.addEventListener("click", onCancel);
}

document.getElementById("btnRefreshVault").addEventListener("click", refreshVault);
document.getElementById("vaultSearchInput").addEventListener("input", renderVaultList);

// --- fragment preview ("identity card" per fragment) ---

// Short human-readable reference, not a stored value — just derived from the
// file's own id so the same fragment always shows the same ID.
function fragmentIdFor(fileId, index) {
  const short = fileId.replace(/-/g, "").slice(0, 4).toUpperCase();
  return `SV-${short}-${String(index).padStart(2, "0")}`;
}

async function openFragmentPreview(file) {
  const overlay = document.getElementById("fragmentPreviewModal");
  const grid = document.getElementById("fragmentPreviewGrid");
  const closeBtn = document.getElementById("fragmentPreviewClose");

  document.getElementById("fragmentPreviewTitle").textContent = file.filename;
  document.getElementById("fragmentPreviewSub").textContent =
    `${file.totalFragments} fragments · threshold ${file.threshold} · created ${fmtDate(file.createdAt)}`;

  const labels = file.fragmentLabels || {};
  const pwText = file.passwordProtected ? "Yes" : "No";

  let html = "";
  for (let i = 1; i <= file.totalFragments; i++) {
    const label = labels[i];
    html += `
      <div class="fragment-card" data-frag="${i}">
        <div class="fragment-num">Fragment ${i} of ${file.totalFragments}</div>
        <div class="fragment-id">${fragmentIdFor(file.fileId, i)}</div>
        <div class="fragment-meta">Required threshold: ${file.threshold}</div>
        <div class="fragment-meta">Created: ${fmtDate(file.createdAt)}</div>
        <div class="fragment-meta">Password protected: ${pwText}</div>
        ${label ? `<div class="fragment-label">→ ${label}</div>` : ""}
        <div class="fragment-status pending" data-role="status">Checking…</div>
      </div>`;
  }
  grid.innerHTML = html;
  overlay.classList.remove("hidden");

  const onClose = () => {
    overlay.classList.add("hidden");
    closeBtn.removeEventListener("click", onClose);
  };
  closeBtn.addEventListener("click", onClose);

  try {
    const results = await invoke("check_vault_file_integrity", { fileId: file.fileId });
    results.forEach((ok, idx) => {
      const statusEl = grid.querySelector(`[data-frag="${idx + 1}"] [data-role="status"]`);
      if (!statusEl) return;
      statusEl.textContent = ok ? "Integrity: Valid" : "Integrity: Corrupted";
      statusEl.className = "fragment-status " + (ok ? "ok" : "bad");
    });
  } catch (err) {
    grid.querySelectorAll('[data-role="status"]').forEach((el) => {
      el.textContent = "Integrity: Unknown";
    });
    toast("Could not verify fragment integrity: " + err, "err");
  }
}

// --- reconstruct tab (select individual fragment files) ---

// collected fragment file paths
let fragmentPaths = [];
let fragmentInfo = null;

// select fragment files (multi-select)
async function pickFragments() {
  const selected = await open({
    multiple: true,
    directory: false,
    title: "Select fragment files (.svf / .svf3)",
      filters: [{ name: "SecureVault Fragments", extensions: ["svf", "svf3"] }, { name: "All Files", extensions: ["*"] }],

  });
  if (!selected) return;

  // selected could be a single path string or an array
  const paths = Array.isArray(selected) ? selected : [selected];

  // add new paths, avoiding duplicates
  for (const p of paths) {
    if (!fragmentPaths.includes(p)) {
      fragmentPaths.push(p);
      const name = p.split(/[\\/]/).pop();
      logTo("importConsole", `Added: ${name}`, "ok");
    }
  }

  updateFragmentDisplay();
  inspectLoadedFragments();
}

function updateFragmentDisplay() {
  const pill = document.getElementById("importPickedFiles");
  if (fragmentPaths.length === 0) {
    pill.classList.add("hidden");
    document.getElementById("importDropContent").style.opacity = "1";
    return;
  }

  const names = fragmentPaths.map((p) => p.split(/[\\/]/).pop());
  pill.textContent = names.join(", ");
  pill.classList.remove("hidden");
  document.getElementById("importDropContent").style.opacity = "0.4";
}

async function inspectLoadedFragments() {
  if (fragmentPaths.length === 0) return;

  try {
    fragmentInfo = await invoke("inspect_fragments", {
      fragmentPaths: fragmentPaths,
    });
    const status = fragmentInfo.enoughToReconstruct
      ? "Ready to reconstruct"
      : `Need ${fragmentInfo.threshold - fragmentInfo.fragmentsLoaded} more`;

    const lock = fragmentInfo.passwordProtected ? " · password protected" : "";

    document.getElementById("importInfo").textContent =
      `${fragmentInfo.filename} · ${fmtBytes(fragmentInfo.size)} · ` +
      `${fragmentInfo.fragmentsLoaded} of ${fragmentInfo.total} fragments · ` +
      `threshold ${fragmentInfo.threshold} · ${status}${lock}`;
    document.getElementById("importInfoCard").classList.remove("hidden");
    logTo("importConsole",
      `${fragmentInfo.fragmentsLoaded} fragment(s) loaded for "${fragmentInfo.filename}"`,
      "ok");
  } catch (err) {
    logTo("importConsole", "Could not read fragments: " + err, "err");
    toast("Error reading fragments", "err");
  }
}

document.getElementById("importDropZone").addEventListener("click", pickFragments);
document.getElementById("btnImportAddMore").addEventListener("click", pickFragments);

document.getElementById("btnImport").addEventListener("click", async () => {
  if (fragmentPaths.length === 0) {
    logTo("importConsole", "No fragments selected", "warn");
    return;
  }

  if (fragmentInfo && !fragmentInfo.enoughToReconstruct) {
    logTo("importConsole",
      `Not enough fragments: need ${fragmentInfo.threshold}, have ${fragmentInfo.fragmentsLoaded}`,
      "warn");
    toast(`Need at least ${fragmentInfo.threshold} fragments`, "err");
    return;
  }

  // prompt for password if needed
  let password = null;
  if (fragmentInfo && fragmentInfo.passwordProtected) {
    password = await askPassword(
      "Password Required",
      `"${fragmentInfo.filename}" requires a password to reconstruct.`,
      (pw) => invoke("verify_fragment_password", { fragmentPaths: fragmentPaths, password: pw })
    );
    if (password === null) return;
  }

  const btn = document.getElementById("btnImport");
  btn.disabled = true;
  logTo("importConsole", "Reconstructing and storing in vault…", "info");

  const prog = document.getElementById("importProgress");
  const bar = document.getElementById("importProgressBar");
  const footer = document.getElementById("importProgressFooter");
  const lbl = document.getElementById("importProgressLabel");
  const timeEl = document.getElementById("importTimeRemaining");

  prog.classList.remove("hidden");
  footer.classList.remove("hidden");
  bar.style.width = "2%";
  lbl.textContent = "Starting…";
  timeEl.textContent = "";

  const startMs = Date.now();
  const operationId = crypto.randomUUID();
  const pauseBtn = document.getElementById("btnImportPause");
  const cancelBtn = document.getElementById("btnImportCancel");
  let paused = false;

  pauseBtn.classList.remove("hidden");
  cancelBtn.classList.remove("hidden");
  pauseBtn.disabled = false;
  cancelBtn.disabled = false;
  pauseBtn.textContent = "Pause";

  pauseBtn.onclick = async () => {
    paused = !paused;
    await invoke(paused ? "pause_operation" : "resume_operation", { operationId });
    pauseBtn.textContent = paused ? "Resume" : "Pause";
  };
  cancelBtn.onclick = async () => {
    cancelBtn.disabled = true;
    await invoke("cancel_operation", { operationId });
  };

  const unlistenImport = await listen("import-progress", ({ payload }) => {
    const { percent, message } = payload;
    bar.style.width = percent + "%";
    lbl.textContent = message;

    if (percent > 5 && percent < 100) {
      const elapsed = Date.now() - startMs;
      const totalEstimated = elapsed / (percent / 100);
      const remaining = Math.max(0, totalEstimated - elapsed);
      timeEl.textContent = fmtDuration(remaining) + " remaining";
    } else if (percent === 100) {
      timeEl.textContent = `Done in ${fmtDuration(Date.now() - startMs)}`;
    }
  });

  try {
    const result = await invoke("reconstruct_from_fragments", {
      fragmentPaths: fragmentPaths,
      password: password,
      operationId,
    });
    bar.style.width = "100%";
    lbl.textContent = "Done!";
    logTo("importConsole", result.message, "ok");
    toast("File reconstructed and stored in vault", "ok");
    resetImport();
    refreshVault();
  } catch (err) {
    if (isCancelled(err)) {
      logTo("importConsole", "Cancelled", "info");
      toast("Import cancelled", "ok");
      lbl.textContent = "Cancelled";
    } else {
      logTo("importConsole", "Error: " + err, "err");
      toast("Reconstruction failed: " + err, "err");
      lbl.textContent = "Failed";
    }
    timeEl.textContent = "";
  } finally {
    btn.disabled = false;
    pauseBtn.classList.add("hidden");
    cancelBtn.classList.add("hidden");
    unlistenImport();
  }
});

document.getElementById("btnImportReset").addEventListener("click", resetImport);

function resetImport() {
  fragmentPaths = [];
  fragmentInfo = null;
  document.getElementById("importPickedFiles").classList.add("hidden");
  document.getElementById("importDropContent").style.opacity = "1";
  document.getElementById("importInfoCard").classList.add("hidden");
  document.getElementById("importProgress").classList.add("hidden");
  document.getElementById("importProgressFooter").classList.add("hidden");
  document.getElementById("importProgressBar").style.width = "0%";
  document.getElementById("importProgressLabel").textContent = "";
  document.getElementById("importTimeRemaining").textContent = "";
  document.getElementById("btnImportPause").classList.add("hidden");
  document.getElementById("btnImportCancel").classList.add("hidden");
}

// --- drag and drop ---

async function setupDragDrop() {
  const splitZone  = document.getElementById("splitDropZone");
  const importZone = document.getElementById("importDropZone");

  // Which panel is currently active?
  function activePanelId() {
    return document.querySelector(".panel.active")?.id ?? "";
  }

  try {
    await getCurrentWebview().onDragDropEvent(async (event) => {
      const type  = event.payload.type;   // "enter" | "over" | "drop" | "leave" | "cancel"
      const paths = event.payload.paths ?? [];
      const panel = activePanelId();

      // ── visual hover state ──────────────────────────────────────────
      if (type === "enter" || type === "over") {
        if (panel === "panel-split")  splitZone.classList.add("drag-over");
        if (panel === "panel-import") importZone.classList.add("drag-over");
        return;
      }
      if (type === "leave" || type === "cancel") {
        splitZone.classList.remove("drag-over");
        importZone.classList.remove("drag-over");
        return;
      }

      // ── drop ────────────────────────────────────────────────────────
      splitZone.classList.remove("drag-over");
      importZone.classList.remove("drag-over");

      if (paths.length === 0) return;

      if (panel === "panel-split") {
        // single-file vault add — use first dropped file
        const filePath = paths[0];
        const name = filePath.split(/[\\/]/).pop();
        splitFilePath = filePath;
        const pill = document.getElementById("splitPickedFile");
        pill.textContent = name;
        pill.classList.remove("hidden");
        showFileNameRow(name);
        document.getElementById("splitDropContent").style.opacity = "0.4";
        logTo("splitConsole", `File dropped: ${name}`, "ok");
        try {
          splitFileSize = await invoke("get_file_size", { filePath });
          await updateSplitEstimate();
          showRecommendBanner(splitFileSize);
          await showCipherRecommendation(splitFileSize);
          logTo("splitConsole", `Size: ${fmtBytes(splitFileSize)}`, "info");
        } catch (err) {
          logTo("splitConsole", `Could not read file size: ${err}`, "warn");
        }

      } else if (panel === "panel-import") {
        // fragment import — accept all dropped files
        for (const p of paths) {
          if (!fragmentPaths.includes(p)) {
            fragmentPaths.push(p);
            const n = p.split(/[\\/]/).pop();
            const pill = document.getElementById("importPickedFiles");
            pill.textContent = `${fragmentPaths.length} fragment(s) selected`;
            pill.classList.remove("hidden");
          }
        }
        document.getElementById("importDropContent").style.opacity = "0.4";
        await loadFragmentInfo();
      }
    });
  } catch {
    // running in browser preview — drag-drop API not available, silently skip
  }
}

// --- activity log ---

const ACTIVITY_LABELS = {
  added: "Added",
  downloaded: "Downloaded",
  shared: "Shared",
  deleted: "Deleted",
  reconstructed: "Reconstructed",
};
const ACTIVITY_STYLES = {
  added: "ok",
  reconstructed: "ok",
  deleted: "err",
  shared: "accent",
  downloaded: "info",
};

async function refreshActivityLog() {
  const list = document.getElementById("activityList");
  try {
    const entries = await invoke("get_activity_log");
    if (entries.length === 0) {
      list.innerHTML = `<div class="log-line"><span class="log-msg info">No activity yet.</span></div>`;
      return;
    }
    list.innerHTML = entries.map((e) => {
      const label = ACTIVITY_LABELS[e.action] || e.action;
      const style = ACTIVITY_STYLES[e.action] || "info";
      return `<div class="log-line">
        <span class="log-time">${fmtDateTime(e.timestamp)}</span>
        <span class="log-msg ${style}">${label} "${e.filename}"</span>
      </div>`;
    }).join("");
  } catch (err) {
    list.innerHTML = `<div class="log-line"><span class="log-msg err">Could not load activity: ${err}</span></div>`;
  }
}

document.getElementById("btnClearActivity").addEventListener("click", async () => {
  if (!window.confirm("Clear the activity log? This cannot be undone."))
    return;
  try {
    await invoke("clear_activity_log");
    toast("Activity log cleared", "ok");
    await refreshActivityLog();
  } catch (err) {
    toast("Could not clear activity log: " + err, "err");
  }
});

// --- security / app lock settings ---

async function refreshSecurityStatus() {
  const bioToggle = document.getElementById("biometricToggle");
  const bioHint = document.getElementById("biometricToggleHint");
  const pinToggle = document.getElementById("pinToggle");
  const pinHint = document.getElementById("pinToggleHint");
  const autoLockSelect = document.getElementById("autoLockSelect");
  const autoLockHint = document.getElementById("autoLockHint");

  try {
    const status = await invoke("security_status");

    if (!status.biometricAvailable) {
      bioHint.textContent = "Not available on this device.";
      bioToggle.disabled = true;
      bioToggle.checked = false;
    } else if (status.pinEnabled) {
      bioHint.textContent = "Turn off PIN Lock to use this instead.";
      bioToggle.disabled = true;
      bioToggle.checked = false;
    } else {
      bioHint.textContent = status.biometricEnabled
        ? `Enabled — SecureVault requires ${status.biometryLabel} to open.`
        : `Optionally require ${status.biometryLabel} to open SecureVault.`;
      bioToggle.disabled = false;
      bioToggle.checked = status.biometricEnabled;
    }

    if (status.biometricEnabled) {
      pinHint.textContent = "Turn off Touch ID / Windows Hello to use this instead.";
      pinToggle.disabled = true;
      pinToggle.checked = false;
    } else {
      pinHint.textContent = status.pinEnabled
        ? "Enabled — SecureVault requires your PIN to open."
        : "Optionally require a PIN to open SecureVault.";
      pinToggle.disabled = false;
      pinToggle.checked = status.pinEnabled;
    }

    const lockActive = status.biometricEnabled || status.pinEnabled;
    autoLockSelect.disabled = !lockActive;
    autoLockSelect.value = String(status.autoLockMinutes ?? 0);
    autoLockHint.textContent = lockActive
      ? "Re-lock automatically after inactivity."
      : "Set up Touch ID or a PIN first.";
    setIdleTimeoutMinutes(lockActive ? status.autoLockMinutes : 0);
  } catch (err) {
    bioHint.textContent = "Could not check device support.";
    bioToggle.disabled = true;
    pinHint.textContent = "Could not check status.";
    pinToggle.disabled = true;
    autoLockSelect.disabled = true;
  }
}

document.getElementById("autoLockSelect").addEventListener("change", async (e) => {
  const select = e.target;
  const minutes = parseInt(select.value);
  try {
    await invoke("set_auto_lock_minutes", { minutes });
    setIdleTimeoutMinutes(minutes);
    toast(minutes === 0 ? "Auto-lock turned off" : `Auto-lock set to ${minutes} min`, "ok");
  } catch (err) {
    toast("Could not update auto-lock: " + err, "err");
    await refreshSecurityStatus();
  }
});

document.getElementById("biometricToggle").addEventListener("change", async (e) => {
  const toggle = e.target;
  const wantEnabled = toggle.checked;
  toggle.disabled = true;
  try {
    if (wantEnabled) {
      await invoke("enable_biometric_lock");
      toast("Touch ID / Windows Hello lock enabled", "ok");
    } else {
      await invoke("disable_biometric_lock");
      toast("Touch ID / Windows Hello lock disabled", "ok");
    }
  } catch (err) {
    toggle.checked = !wantEnabled;
    toast("Could not update App Lock: " + err, "err");
  } finally {
    await refreshSecurityStatus();
  }
});

// --- PIN setup modal (two fields: PIN + confirm) ---

const MIN_PIN_LENGTH = 4;

function askPinSetup() {
  return new Promise((resolve) => {
    const overlay = document.getElementById("pinSetupModal");
    const pinInput = document.getElementById("pinSetupInput");
    const confirmInput = document.getElementById("pinSetupConfirmInput");
    const errorEl = document.getElementById("pinSetupError");

    pinInput.value = "";
    confirmInput.value = "";
    errorEl.classList.add("hidden");
    overlay.classList.remove("hidden");
    pinInput.focus();

    const cleanup = () => {
      overlay.classList.add("hidden");
      errorEl.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onCancel = () => { cleanup(); resolve(null); };

    const onConfirm = () => {
      const pin = pinInput.value;
      const confirm = confirmInput.value;
      if (pin.length < MIN_PIN_LENGTH) {
        errorEl.textContent = `PIN must be at least ${MIN_PIN_LENGTH} characters`;
        errorEl.classList.remove("hidden");
        return;
      }
      if (pin !== confirm) {
        errorEl.textContent = "PINs don't match";
        errorEl.classList.remove("hidden");
        return;
      }
      cleanup();
      resolve(pin);
    };

    const confirmBtn = document.getElementById("pinSetupConfirm");
    const cancelBtn = document.getElementById("pinSetupCancel");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

document.getElementById("pinToggle").addEventListener("change", async (e) => {
  const toggle = e.target;
  const wantEnabled = toggle.checked;
  toggle.disabled = true;

  try {
    if (wantEnabled) {
      const pin = await askPinSetup();
      if (pin === null) {
        toggle.checked = false;
        return;
      }
      await invoke("enable_pin_lock", { pin });
      toast("PIN lock enabled", "ok");
    } else {
      const confirmed = await askPassword(
        "Confirm PIN",
        "Enter your current PIN to disable PIN lock.",
        (pw) => invoke("disable_pin_lock", { pin: pw }).then(() => true)
      );
      if (confirmed === null) {
        toggle.checked = true;
        return;
      }
      toast("PIN lock disabled", "ok");
    }
  } catch (err) {
    toggle.checked = !wantEnabled;
    toast("Could not update PIN lock: " + err, "err");
  } finally {
    await refreshSecurityStatus();
  }
});

// --- vault backup / restore ---

const MIN_BACKUP_PASSWORD_LENGTH = 8;

function askBackupPassword() {
  return new Promise((resolve) => {
    const overlay = document.getElementById("backupPasswordModal");
    const pwInput = document.getElementById("backupPasswordInput");
    const confirmInput = document.getElementById("backupPasswordConfirmInput");
    const errorEl = document.getElementById("backupPasswordError");

    pwInput.value = "";
    confirmInput.value = "";
    errorEl.classList.add("hidden");
    overlay.classList.remove("hidden");
    pwInput.focus();

    const cleanup = () => {
      overlay.classList.add("hidden");
      errorEl.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onCancel = () => { cleanup(); resolve(null); };

    const onConfirm = () => {
      const pw = pwInput.value;
      const confirm = confirmInput.value;
      if (pw.length < MIN_BACKUP_PASSWORD_LENGTH) {
        errorEl.textContent = `Backup password must be at least ${MIN_BACKUP_PASSWORD_LENGTH} characters`;
        errorEl.classList.remove("hidden");
        return;
      }
      if (pw !== confirm) {
        errorEl.textContent = "Passwords don't match";
        errorEl.classList.remove("hidden");
        return;
      }
      cleanup();
      resolve(pw);
    };

    const confirmBtn = document.getElementById("backupPasswordConfirm");
    const cancelBtn = document.getElementById("backupPasswordCancel");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

document.getElementById("backupExportBtn").addEventListener("click", async () => {
  const btn = document.getElementById("backupExportBtn");
  const password = await askBackupPassword();
  if (password === null) return;

  const destinationPath = await save({
    title: "Save Vault Backup",
    defaultPath: "securevault-backup.svbackup",
    filters: [{ name: "SecureVault Backup", extensions: ["svbackup"] }],
  });
  if (!destinationPath) return;

  btn.disabled = true;
  const originalText = btn.textContent;
  btn.textContent = "Backing up…";
  try {
    await invoke("export_vault_backup", { password, destinationPath });
    toast("Vault backed up successfully", "ok");
  } catch (err) {
    toast("Backup failed: " + err, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
});

document.getElementById("backupImportBtn").addEventListener("click", async () => {
  const btn = document.getElementById("backupImportBtn");
  const sourcePath = await open({
    title: "Choose a Vault Backup",
    multiple: false,
    filters: [{ name: "SecureVault Backup", extensions: ["svbackup"] }],
  });
  if (!sourcePath) return;

  btn.disabled = true;
  const originalText = btn.textContent;
  btn.textContent = "Restoring…";
  try {
    let restoredCount = 0;
    const confirmed = await askPassword(
      "Restore Vault",
      "Enter the password for this backup.",
      (pw) => invoke("import_vault_backup", { password: pw, sourcePath }).then((res) => {
        restoredCount = res.filesRestored;
        return true;
      })
    );
    if (confirmed === null) return;
    toast(`Restored ${restoredCount} file(s) from backup`, "ok");
    await refreshVault();
  } catch (err) {
    toast("Restore failed: " + err, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
});

// --- lock screen (shared between startup and the auto-lock idle timer) ---

// Renders the lock screen for whichever method is active and wires up its
// unlock control. Uses .onclick/.onkeydown (single-slot) rather than
// addEventListener so calling this more than once — startup, then later
// every time auto-lock fires — never stacks duplicate handlers.
function showLockScreen(status, onUnlocked) {
  document.getElementById("introScreen").classList.add("removed");

  const lockScreen = document.getElementById("lockScreen");
  const errorEl = document.getElementById("lockScreenError");
  const pinRow = document.getElementById("lockScreenPinRow");
  const pinInput = document.getElementById("lockScreenPinInput");
  const bioBtn = document.getElementById("btnUnlockBiometric");
  const pinBtn = document.getElementById("btnUnlockPin");

  errorEl.classList.add("hidden");
  lockScreen.classList.remove("fade-out", "removed", "hidden");
  pinRow.classList.add("hidden");
  bioBtn.classList.add("hidden");
  pinInput.value = "";
  pinInput.disabled = false;
  bioBtn.disabled = false;
  pinBtn.disabled = false;

  const dismiss = async () => {
    lockScreen.classList.add("fade-out");
    setTimeout(() => lockScreen.classList.add("removed"), 550);
    resetIdleTimer();
    await onUnlocked();
  };

  if (status.pinEnabled) {
    pinRow.classList.remove("hidden");
    pinInput.focus();

    const tryUnlock = async () => {
      errorEl.classList.add("hidden");
      pinBtn.disabled = true;
      pinInput.disabled = true;
      try {
        await invoke("unlock_vault_with_pin", { pin: pinInput.value });
        await dismiss();
      } catch (err) {
        errorEl.textContent = String(err);
        errorEl.classList.remove("hidden");
        pinBtn.disabled = false;
        pinInput.disabled = false;
        pinInput.select();
      }
    };
    pinBtn.onclick = tryUnlock;
    pinInput.onkeydown = (e) => { if (e.key === "Enter") tryUnlock(); };
  } else {
    bioBtn.classList.remove("hidden");
    bioBtn.onclick = async () => {
      errorEl.classList.add("hidden");
      bioBtn.disabled = true;
      try {
        await invoke("unlock_vault_with_biometric");
        await dismiss();
      } catch (err) {
        errorEl.textContent = String(err);
        errorEl.classList.remove("hidden");
      } finally {
        bioBtn.disabled = false;
      }
    };
  }
}

// --- auto-lock idle timer ---

let idleTimeoutMinutes = 0;
let idleLastActivity = Date.now();
let idleCheckRunning = false;

function setIdleTimeoutMinutes(minutes) {
  idleTimeoutMinutes = minutes || 0;
}

function resetIdleTimer() {
  idleLastActivity = Date.now();
}

["mousemove", "mousedown", "keydown", "wheel", "touchstart"].forEach((evt) => {
  document.addEventListener(evt, resetIdleTimer, { passive: true });
});

setInterval(async () => {
  if (!idleTimeoutMinutes || idleCheckRunning) return;
  const lockScreenHidden = document.getElementById("lockScreen").classList.contains("hidden");
  if (!lockScreenHidden) return; // already locked, nothing to do

  const idleMs = Date.now() - idleLastActivity;
  if (idleMs < idleTimeoutMinutes * 60 * 1000) return;

  idleCheckRunning = true;
  try {
    await invoke("lock_vault");
    const status = await invoke("security_status");
    showLockScreen(status, refreshVault);
  } catch {
    // browser preview, or no lock method set up — nothing to do
  } finally {
    idleCheckRunning = false;
  }
}, 5000);

// --- init ---

updateThresholdVisual();
setupDragDrop();

// Show the intro screen for at least `minDelay` ms, but also wait for the
// vault list to actually finish loading — whichever takes longer — so it
// never feels like a flicker, and never hides a still-loading file list.
async function startApp() {
  const minDelay = new Promise((resolve) => setTimeout(resolve, 1200));
  await Promise.all([refreshVault(), minDelay]);

  const intro = document.getElementById("introScreen");
  intro.classList.add("fade-out");
  setTimeout(() => intro.classList.add("removed"), 550);
}

(async () => {
  let status = null;
  try {
    status = await invoke("security_status");
  } catch {
    // running in browser preview — invoke() isn't available; behave as unlocked
  }

  if (!status || !status.vaultLocked) {
    await startApp();
    return;
  }

  // App Lock is on and the vault hasn't been unlocked yet this session —
  // skip straight to the lock screen instead of the intro animation.
  showLockScreen(status, startApp);
})();
