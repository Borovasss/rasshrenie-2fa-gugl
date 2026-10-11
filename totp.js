"use strict";

const GAuthTOTP = (() => {
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  function base32Decode(str) {
    const clean = String(str || "")
      .toUpperCase()
      .replace(/[\s\-]/g, "")
      .replace(/=+$/, "");
    let bits = 0;
    let value = 0;
    const out = [];
    for (const ch of clean) {
      const idx = B32.indexOf(ch);
      if (idx === -1) throw new Error("Недопустимый символ base32: " + ch);
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    if (out.length === 0) throw new Error("Пустой секрет");
    return new Uint8Array(out);
  }

  async function hotp(keyBytes, counter, digits, algo) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 2 ** 32));
    view.setUint32(4, counter >>> 0);
    const hash = algo === "SHA-256" ? "SHA-256" : algo === "SHA-512" ? "SHA-512" : "SHA-1";
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash },
      false,
      ["sign"]
    );
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
    const offset = sig[sig.length - 1] & 0x0f;
    const bin =
      ((sig[offset] & 0x7f) << 24) |
      (sig[offset + 1] << 16) |
      (sig[offset + 2] << 8) |
      sig[offset + 3];
    return String(bin % 10 ** digits).padStart(digits, "0");
  }

  async function generate(secretBase32, opts = {}) {
    const period = opts.period || 30;
    const digits = opts.digits || 6;
    const algo = opts.algo || "SHA-1";
    const now = opts.now || Date.now();
    let counter;
    if (opts.type === "hotp") {
      counter = opts.counter || 0;
    } else {
      counter = Math.floor(now / 1000 / period);
    }
    return hotp(base32Decode(secretBase32), counter, digits, algo);
  }

  function secondsLeft(period = 30) {
    return period - (Math.floor(Date.now() / 1000) % period);
  }

  function formatCode(code) {
    const mid = Math.ceil(code.length / 2);
    return code.slice(0, mid) + " " + code.slice(mid);
  }

  /* ---------------- otpauth:// ---------------- */

  function parseOtpauth(uri) {
    let url;
    try {
      url = new URL(uri.trim());
    } catch {
      throw new Error("Некорректная ссылка otpauth://");
    }
    if (url.protocol !== "otpauth:") throw new Error("Ссылка должна быть otpauth://");
    const type = url.hostname.toLowerCase();
    if (type !== "totp" && type !== "hotp") throw new Error("Поддерживается только totp/hotp");
    const path = decodeURIComponent(url.pathname.replace(/^\//, ""));
    let issuer = url.searchParams.get("issuer") || "";
    let name = path;
    const colon = path.indexOf(":");
    if (colon !== -1) {
      if (!issuer) issuer = path.slice(0, colon).trim();
      name = path.slice(colon + 1).trim();
    }
    const secret = (url.searchParams.get("secret") || "").replace(/\s/g, "");
    if (!secret) throw new Error("В ссылке нет параметра secret");
    const digits = parseInt(url.searchParams.get("digits") || "6", 10) || 6;
    const period = parseInt(url.searchParams.get("period") || "30", 10) || 30;
    const algoRaw = (url.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const counter = parseInt(url.searchParams.get("counter") || "0", 10) || 0;
    return newAccount({
      name: name || issuer || "Аккаунт",
      issuer,
      secret: secret.toUpperCase(),
      digits,
      period,
      type,
      counter,
      algo: algoRaw === "SHA256" ? "SHA-256" : algoRaw === "SHA512" ? "SHA-512" : "SHA-1"
    });
  }

  /* ------------- otpauth-migration:// (protobuf) ------------- */

  function readVarint(bytes, pos) {
    let result = 0;
    let shift = 0;
    let b;
    do {
      if (pos >= bytes.length) throw new Error("Обрыв protobuf");
      b = bytes[pos++];
      result += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (shift > 49) throw new Error("Слишком длинный varint");
    } while (b & 0x80);
    return [result, pos];
  }

  function readFields(bytes) {
    const fields = {};
    let pos = 0;
    while (pos < bytes.length) {
      let key;
      [key, pos] = readVarint(bytes, pos);
      const num = Math.floor(key / 8);
      const wire = key & 7;
      if (wire === 0) {
        let v;
        [v, pos] = readVarint(bytes, pos);
        fields[num] = (fields[num] || []).concat([v]);
      } else if (wire === 2) {
        let len;
        [len, pos] = readVarint(bytes, pos);
        if (pos + len > bytes.length) throw new Error("Обрыв protobuf (len)");
        const v = bytes.subarray(pos, pos + len);
        pos += len;
        fields[num] = (fields[num] || []).concat([v]);
      } else if (wire === 5) {
        pos += 4;
      } else if (wire === 1) {
        pos += 8;
      } else {
        throw new Error("Неизвестный wire-type: " + wire);
      }
    }
    return fields;
  }

  const dec = new TextDecoder("utf-8", { fatal: false });

  function parseMigration(uri) {
    const raw = String(uri || "").trim();
    const m = raw.match(/^otpauth-migration:\/\/[^?]*\?(.*)$/i);
    if (!m) throw new Error("Не ссылка otpauth-migration://");
    const params = new URLSearchParams(m[1]);
    let b64 = params.get("data") || "";
    if (!b64) throw new Error("Нет параметра data");
    b64 = decodeURIComponent(b64).replace(/\s/g, "");
    while (b64.length % 4) b64 += "=";
    const norm = b64.replace(/-/g, "+").replace(/_/g, "/");
    let bin;
    try {
      bin = atob(norm);
    } catch {
      throw new Error("data не является base64");
    }
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

    const payload = readFields(bytes);
    const list = payload[1] || [];
    if (!list.length) throw new Error("В QR нет аккаунтов");

    const accounts = [];
    for (const entry of list) {
      const f = readFields(entry);
      const secretBytes = f[1] && f[1][0];
      if (!secretBytes || !secretBytes.length) continue;
      const algoN = (f[4] && f[4][0]) || 1;
      const digitsN = (f[5] && f[5][0]) || 1;
      const typeN = (f[6] && f[6][0]) || 2;
      accounts.push(
        newAccount({
          name: dec.decode(f[2] && f[2][0]) || "Аккаунт",
          issuer: dec.decode(f[3] && f[3][0]) || "",
          secret: base32Encode(secretBytes),
          digits: digitsN === 2 ? 8 : 6,
          period: 30,
          type: typeN === 1 ? "hotp" : "totp",
          counter: (f[7] && f[7][0]) || 0,
          algo: algoN === 2 ? "SHA-256" : algoN === 3 ? "SHA-512" : "SHA-1"
        })
      );
    }
    if (!accounts.length) throw new Error("Не удалось разобрать аккаунты из QR");
    return accounts;
  }

  function base32Encode(bytes) {
    let bits = 0;
    let value = 0;
    let out = "";
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  /* ------------- универсальный разбор текста из QR ------------- */

  function parseText(text) {
    const t = String(text || "").trim();
    if (/^otpauth-migration:/i.test(t)) return parseMigration(t);
    if (/^otpauth:/i.test(t)) return [parseOtpauth(t)];
    throw new Error("QR не похож на otpauth:// или otpauth-migration://");
  }

  function newAccount(o) {
    return {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
      name: o.name,
      issuer: o.issuer || "",
      secret: (o.secret || "").toUpperCase().replace(/\s/g, ""),
      digits: o.digits === 8 ? 8 : 6,
      period: o.period || 30,
      type: o.type === "hotp" ? "hotp" : "totp",
      counter: o.counter || 0,
      algo: o.algo === "SHA-256" || o.algo === "SHA-512" ? o.algo : "SHA-1"
    };
  }

  return {
    base32Decode,
    base32Encode,
    generate,
    secondsLeft,
    formatCode,
    parseOtpauth,
    parseMigration,
    parseText,
    newAccount
  };
})();
