"use strict";

let accounts = [];
let timerId = null;
let vaultKeyB64 = null;

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["settings"]).then((data) => {
    const settings = Object.assign({ autofill: true }, data.settings || {});
    chrome.storage.local.set({ settings });
  });
});

chrome.storage.local.get(["accounts", "vaultKey"]).then((data) => {
  accounts = Array.isArray(data.accounts) ? data.accounts : [];
  vaultKeyB64 = data.vaultKey || null;
  start();
});

chrome.storage.onChanged.addListener((ch, area) => {
  if (area !== "local") return;
  if (ch.accounts) {
    accounts = ch.accounts.newValue || [];
    start();
    scheduleVaultSync();
  }
  if (ch.vaultKey) {
    vaultKeyB64 = ch.vaultKey.newValue || null;
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "sync-vault") {
    syncVault()
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ ok: false, error: String((e && e.message) || e) }));
    return true;
  }
});

function start() {
  if (timerId) clearInterval(timerId);
  if (!accounts.length) {
    chrome.action.setBadgeText({ text: "" });
    return;
  }
  tick();
  timerId = setInterval(tick, 1000);
}

function tick() {
  const period = accounts[0].period || 30;
  const left = period - (Math.floor(Date.now() / 1000) % period);
  const expiring = left <= 5;
  chrome.action.setBadgeBackgroundColor({ color: expiring ? "#fbbc04" : "#4285f4" });
  chrome.action.setBadgeText({ text: String(left) });
}

/* ---------- vault → файл на ПК ---------- */

const VAULT_MAGIC = "GAUTH1"; // 6 байт

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getOrCreateVaultKey() {
  if (vaultKeyB64) return b64ToBytes(vaultKeyB64);
  const raw = crypto.getRandomValues(new Uint8Array(32));
  vaultKeyB64 = bytesToB64(raw);
  await chrome.storage.local.set({ vaultKey: vaultKeyB64 });
  return raw;
}

function downloadDataUrl(filename, dataUrl) {
  return new Promise((resolve, reject) => {
    chrome.downloads.download(
      { url: dataUrl, filename, conflictAction: "overwrite", saveAs: false },
      (id) => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(id);
      }
    );
  });
}

let vaultSyncTimer = null;
function scheduleVaultSync() {
  clearTimeout(vaultSyncTimer);
  vaultSyncTimer = setTimeout(() => {
    syncVault().catch(() => {});
  }, 1200);
}

async function syncVault() {
  if (!accounts.length) return { ok: false, error: "Нет аккаунтов" };

  const key = await getOrCreateVaultKey();

  const payload = {
    accounts: accounts.map((a) => ({
      name: a.name,
      issuer: a.issuer || "",
      secret: a.secret,
      digits: a.digits || 6,
      period: a.period || 30,
      type: a.type || "totp",
      counter: a.counter || 0,
      algo: a.algo || "SHA-1"
    }))
  };
  const pt = new TextEncoder().encode(JSON.stringify(payload));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pt));

  const magic = new TextEncoder().encode(VAULT_MAGIC);
  const blob = new Uint8Array(6 + 1 + 12 + ct.length);
  blob.set(magic, 0);
  blob[6] = 1;
  blob.set(iv, 7);
  blob.set(ct, 19);

  await downloadDataUrl(
    "GAuth/vault.gauth",
    "data:application/octet-stream;base64," + bytesToB64(blob)
  );
  await downloadDataUrl(
    "GAuth/device.key",
    "data:text/plain;base64," + bytesToB64(new TextEncoder().encode(vaultKeyB64))
  );

  return { ok: true, count: accounts.length };
}
