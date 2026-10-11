"use strict";

(() => {
  const SELECTORS = [
    'input[autocomplete="one-time-code"]',
    'input[name="otp"]',
    'input[name="totp"]',
    'input[name="code"]',
    'input[id="totpPin"]',
    'input[id="code"]'
  ];

  let settings = { autofill: true };
  let accounts = [];
  let filled = false;

  chrome.storage.local.get(["accounts", "settings"]).then((data) => {
    accounts = Array.isArray(data.accounts) ? data.accounts : [];
    settings = Object.assign({ autofill: true }, data.settings || {});
    if (settings.autofill && accounts.length) {
      setTimeout(tryFill, 800);
      observe();
    }
  });

  chrome.storage.onChanged.addListener((ch, area) => {
    if (area !== "local") return;
    if (ch.accounts) accounts = ch.accounts.newValue || [];
    if (ch.settings) settings = Object.assign({ autofill: true }, ch.settings.newValue || {});
    filled = false;
  });

  function findField() {
    for (const sel of SELECTORS) {
      const el = document.querySelector(sel);
      if (el && el.offsetParent !== null && !el.disabled && !el.readOnly) return el;
    }
    return null;
  }

  function pickAccount() {
    if (!accounts.length) return null;
    const host = location.hostname;
    const byHost = accounts.find(
      (a) =>
        (a.issuer && host.includes(a.issuer.toLowerCase())) ||
        (a.name && host.includes(a.name.toLowerCase().split("@").pop()))
    );
    return byHost || accounts[0];
  }

  async function tryFill() {
    if (filled || !settings.autofill || !accounts.length) return;
    const field = findField();
    if (!field || field.value) return;
    const acc = pickAccount();
    if (!acc) return;
    try {
      const code = await GAuthTOTP.generate(acc.secret, {
        digits: acc.digits,
        period: acc.period,
        algo: acc.algo,
        type: acc.type,
        counter: acc.counter
      });
      const proto = Object.getPrototypeOf(field);
      const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
      if (setter) setter.call(field, code);
      else field.value = code;
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
      filled = true;
      flash(field);
    } catch (e) {
      console.warn("[GAuth]", e);
    }
  }

  function flash(field) {
    field.style.outline = "2px solid #34a853";
    field.style.transition = "outline 1.5s";
    setTimeout(() => { field.style.outline = ""; }, 300);
  }

  function observe() {
    const mo = new MutationObserver(() => {
      if (!filled) setTimeout(tryFill, 400);
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    setInterval(tryFill, 2000);
  }
})();
