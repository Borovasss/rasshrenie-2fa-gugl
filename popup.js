"use strict";

const $ = (sel) => document.querySelector(sel);

const AVATAR_COLORS = [
  "#4285f4", "#ea4335", "#fbbc04", "#34a853",
  "#a142f4", "#24c1e0", "#ff7043", "#9c27b0"
];

let accounts = [];
let settings = { autofill: true };
let timerId = null;

/* ---------- storage ---------- */

async function loadState() {
  const data = await chrome.storage.local.get(["accounts", "settings"]);
  accounts = Array.isArray(data.accounts) ? data.accounts : [];
  settings = Object.assign({ autofill: true }, data.settings || {});
}

async function saveState() {
  await chrome.storage.local.set({ accounts, settings });
}

/* ---------- render ---------- */

function avatarColor(str) {
  let h = 0;
  for (const c of str) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function initials(acc) {
  const src = (acc.issuer || acc.name || "?").trim();
  return src[0].toUpperCase();
}

async function render() {
  const list = $("#list");
  list.innerHTML = "";
  $("#empty").classList.toggle("hidden", accounts.length > 0);

  for (const acc of accounts) {
    const card = document.createElement("div");
    card.className = "card";

    const avatar = document.createElement("div");
    avatar.className = "avatar";
    avatar.style.background = avatarColor(acc.secret);
    avatar.textContent = initials(acc);

    const meta = document.createElement("div");
    meta.className = "meta";

    const issuer = document.createElement("div");
    issuer.className = "issuer";
    issuer.textContent = acc.issuer || "—";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = acc.name;

    const code = document.createElement("div");
    code.className = "code";
    code.textContent = "••• •••";

    meta.append(issuer, name, code);

    const del = document.createElement("button");
    del.className = "del";
    del.title = "Удалить";
    del.textContent = "✕";
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!confirm(`Удалить аккаунт «${acc.name}»?`)) return;
      accounts = accounts.filter((a) => a.id !== acc.id);
      saveState().then(render);
    });

    const bar = document.createElement("div");
    bar.className = "bar";

    card.append(avatar, meta, del, bar);
    card._acc = acc;
    card._codeEl = code;
    card._barEl = bar;
    list.appendChild(card);

    code.addEventListener("click", () => copyCode(acc, code));
  }

  startTimer();
}

/* ---------- codes & timer ---------- */

async function tick() {
  const cards = document.querySelectorAll(".card");
  for (const card of cards) {
    const acc = card._acc;
    try {
      const raw = await GAuthTOTP.generate(acc.secret, {
        digits: acc.digits,
        period: acc.period,
        algo: acc.algo,
        type: acc.type,
        counter: acc.counter
      });
      const period = acc.period || 30;
      const left = GAuthTOTP.secondsLeft(period);
      const pct = (left / period) * 100;
      const expiring = left <= 5;

      if (card._codeEl.textContent !== GAuthTOTP.formatCode(raw)) {
        card._codeEl.textContent = GAuthTOTP.formatCode(raw);
      }
      card._codeEl.classList.toggle("expiring", expiring);
      card._barEl.style.width = pct + "%";
      card._barEl.classList.toggle("expiring", expiring);
      card._raw = raw;
    } catch (e) {
      card._codeEl.textContent = "ошибка";
      card._codeEl.title = String(e);
    }
  }
}

function startTimer() {
  if (timerId) clearInterval(timerId);
  tick();
  timerId = setInterval(tick, 1000);
}

async function copyCode(acc, codeEl) {
  let raw = codeEl.textContent.replace(/\s/g, "");
  if (/^\d+$/.test(raw) && raw.length >= 6) {
    // уже сгенерирован
  } else {
    raw = await GAuthTOTP.generate(acc.secret, {
      digits: acc.digits,
      period: acc.period,
      algo: acc.algo,
      type: acc.type,
      counter: acc.counter
    });
  }
  try {
    await navigator.clipboard.writeText(raw);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = raw;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  showToast("Скопировано: " + raw);
}

function showToast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), 1600);
}

/* ---------- modal helpers ---------- */

function openModal(id) { $(id).classList.remove("hidden"); }
function closeModal(id) { $(id).classList.add("hidden"); }

/* ---------- add account ---------- */

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === tab)
  );
  ["qr", "link", "manual"].forEach((t) =>
    $("#tab-" + t).classList.toggle("hidden", t !== tab)
  );
  $("#addError").classList.add("hidden");
}

function activeTab() {
  return document.querySelector(".tab.active").dataset.tab;
}

function showError(msg) {
  const el = $("#addError");
  el.textContent = msg;
  el.classList.remove("hidden");
}

function addMany(list) {
  let added = 0;
  let skipped = 0;
  for (const acc of list) {
    if (!acc || !acc.secret) { skipped++; continue; }
    try {
      GAuthTOTP.base32Decode(acc.secret);
    } catch {
      skipped++;
      continue;
    }
    if (accounts.some((a) => a.secret === acc.secret)) {
      skipped++;
      continue;
    }
    if (!acc.id) acc.id = String(Date.now() + Math.random());
    accounts.push(acc);
    added++;
  }
  return { added, skipped };
}

async function addAccount(acc) {
  if (!acc || !acc.secret) throw new Error("Пустой аккаунт");
  GAuthTOTP.base32Decode(acc.secret);
  if (accounts.some((a) => a.secret === acc.secret)) {
    throw new Error("Такой аккаунт уже добавлен");
  }
  if (!acc.id) acc.id = String(Date.now() + Math.random());
  accounts.push(acc);
  await saveState();
  await render();
}

/* Ищет ВСЕ QR на картинке: находит один — закрашивает его — ищет следующий */
function decodeAllQRCodes(img) {
  const canvas = document.createElement("canvas");
  const MAX = 2400;
  const nw = img.naturalWidth || img.width;
  const nh = img.naturalHeight || img.height;
  const scale = Math.min(1, MAX / Math.max(nw, nh));
  canvas.width = Math.max(1, Math.round(nw * scale));
  canvas.height = Math.max(1, Math.round(nh * scale));
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  const found = [];
  for (let i = 0; i < 6; i++) {
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const res = jsQR(data.data, data.width, data.height, {
      inversionAttempts: "attemptBoth"
    });
    if (!res || !res.data) break;
    found.push(res.data);

    // закрасить найденный QR, чтобы найти следующий на том же скриншоте
    const loc = res.location;
    if (!loc) break;
    const xs = [loc.topLeftCorner.x, loc.topRightCorner.x, loc.bottomLeftCorner.x, loc.bottomRightCorner.x];
    const ys = [loc.topLeftCorner.y, loc.topRightCorner.y, loc.bottomLeftCorner.y, loc.bottomRightCorner.y];
    const x0 = Math.max(0, Math.min(...xs) - 8);
    const y0 = Math.max(0, Math.min(...ys) - 8);
    const x1 = Math.min(canvas.width, Math.max(...xs) + 8);
    const y1 = Math.min(canvas.height, Math.max(...ys) + 8);
    ctx.fillStyle = "#fff";
    ctx.fillRect(x0, y0, x1 - x0, y1 - y0);
  }
  return found;
}

async function handleSave() {
  $("#addError").classList.add("hidden");
  try {
    const tab = activeTab();
    if (tab === "qr") {
      const img = $("#qrImg");
      if (!img.src) throw new Error("Сначала выбери изображение QR");
      const texts = decodeAllQRCodes(img);
      if (!texts.length) throw new Error("QR не распознан. Попробуй фото поярче/крупнее, без бликов.");
      const parsed = [];
      let bad = 0;
      for (const t of texts) {
        try {
          parsed.push(...GAuthTOTP.parseText(t));
        } catch {
          bad++;
        }
      }
      if (!parsed.length) throw new Error("QR найден, но формат не распознан (" + texts.length + " шт)");
      const r = addMany(parsed);
      await saveState();
      await render();
      if (r.added === 0) throw new Error("Все " + parsed.length + " аккаунтов уже добавлены");
      showToast(
        "Добавлено: " + r.added +
        (r.skipped ? ", пропущено: " + r.skipped : "") +
        (texts.length > 1 ? " (QR найдено: " + texts.length + ")" : "") +
        (bad ? ", не разобрано: " + bad : "")
      );
    } else if (tab === "link") {
      const text = $("#linkInput").value.trim();
      if (!text) throw new Error("Вставь otpauth:// ссылку");
      const parsed = GAuthTOTP.parseText(text);
      const r = addMany(parsed);
      await saveState();
      await render();
      if (r.added === 0) throw new Error("Ничего не добавлено (уже есть?)");
      showToast("Добавлено: " + r.added);
      $("#linkInput").value = "";
    } else {
      const name = $("#mName").value.trim();
      const secret = $("#mSecret").value.trim().toUpperCase();
      const issuer = $("#mIssuer").value.trim();
      if (!name) throw new Error("Укажи имя аккаунта");
      if (!secret) throw new Error("Укажи секрет");
      await addAccount(GAuthTOTP.newAccount({ name, issuer, secret, digits: 6, period: 30 }));
      showToast("Аккаунт добавлен");
      $("#mName").value = "";
      $("#mIssuer").value = "";
      $("#mSecret").value = "";
    }
    closeModal("#modalAdd");
  } catch (e) {
    showError(e.message || String(e));
  }
}

/* ---------- settings ---------- */

function exportAccounts() {
  if (!accounts.length) return showToast("Нет аккаунтов");
  const payload = accounts.map((a) => ({
    name: a.name,
    issuer: a.issuer,
    secret: a.secret,
    digits: a.digits,
    period: a.period
  }));
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "gauth-backup.json";
  a.click();
  URL.revokeObjectURL(url);
}

/* ---------- wiring ---------- */

async function doSyncVault() {
  const btn = $("#btnSync");
  const st = $("#syncStatus");
  btn.disabled = true;
  st.classList.remove("hidden", "ok", "err");
  st.textContent = "Пишу vault.gauth…";
  try {
    const r = await chrome.runtime.sendMessage({ type: "sync-vault" });
    if (r && r.ok) {
      st.classList.add("ok");
      st.textContent = "✓ GAuth/vault.gauth обновлён (" + r.count + " акк.) → папка загрузок Chrome";
    } else {
      st.classList.add("err");
      st.textContent = "Ошибка: " + ((r && r.error) || "нет ответа");
    }
  } catch (e) {
    st.classList.add("err");
    st.textContent = "Ошибка: " + e;
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadState();
  await render();

  $("#btnAdd").addEventListener("click", () => openModal("#modalAdd"));
  $("#btnCancel").addEventListener("click", () => closeModal("#modalAdd"));
  $("#btnSave").addEventListener("click", handleSave);
  $("#btnSync").addEventListener("click", doSyncVault);
  $("#btnSettings").addEventListener("click", () => {
    $("#optAutofill").checked = settings.autofill;
    openModal("#modalSettings");
  });
  $("#btnSettingsClose").addEventListener("click", async () => {
    settings.autofill = $("#optAutofill").checked;
    await saveState();
    closeModal("#modalSettings");
  });
  $("#btnExport").addEventListener("click", exportAccounts);
  $("#btnClear").addEventListener("click", async () => {
    if (!confirm("Удалить ВСЕ аккаунты? Это необратимо.")) return;
    accounts = [];
    await saveState();
    await render();
    closeModal("#modalSettings");
    showToast("Все аккаунты удалены");
  });

  document.querySelectorAll(".tab").forEach((b) =>
    b.addEventListener("click", () => switchTab(b.dataset.tab))
  );

  $("#qrFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const url = URL.createObjectURL(file);
    const img = $("#qrImg");
    img.onload = () => {
      $("#qrPreview").classList.remove("hidden");
      $("#qrPreview")._src = url;
    };
    img.onerror = () => showError("Не удалось открыть изображение");
    img.src = url;
  });

  document.querySelectorAll(".modal").forEach((m) =>
    m.addEventListener("click", (e) => {
      if (e.target === m) m.classList.add("hidden");
    })
  );
});
