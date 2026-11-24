// =====================================================================
// 設計重點（Safari 相容）：
//   Safari 要求 navigator.credentials.create()/get() 在「使用者點擊」中直接呼叫。
//   因此所有伺服器選項都「事先」取得並轉好格式，按鈕 click 裡第一個動作就是
//   呼叫 create()/get()，中間不 await 任何 fetch。
// =====================================================================

// ---------- Base64URL <-> ArrayBuffer ----------
const b64urlToBuf = s => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;
};
const bufToB64url = buf => {
  let s = "";
  new Uint8Array(buf).forEach(b => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const $ = id => document.getElementById(id);
const show = (text, ok = true) => { $("msg").className = ok ? "ok" : "err"; $("msg").textContent = text; };
const fmt = d => (d ? new Date(d + (d.endsWith("Z") ? "" : "Z")).toLocaleString() : "—");

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ---------- 預先取得的選項 ----------
// 伺服器的 challenge 存在 Session（閒置 5 分鐘失效），所以 4 分鐘就換新的
const OPTIONS_TTL_MS = 4 * 60 * 1000;
const prepared = {
  login: null,      // { options, at }
  addDevice: null,  // { options, at }
  signup: null      // { options, at }
};
const isFresh = p => p && Date.now() - p.at < OPTIONS_TTL_MS;

// 把伺服器回傳的 JSON 轉成 WebAuthn 需要的 ArrayBuffer 格式
function toCreateOptions(o) {
  o.challenge = b64urlToBuf(o.challenge);
  o.user.id = b64urlToBuf(o.user.id);
  (o.excludeCredentials || []).forEach(c => (c.id = b64urlToBuf(c.id)));
  return o;
}
function toGetOptions(o) {
  o.challenge = b64urlToBuf(o.challenge);
  (o.allowCredentials || []).forEach(c => (c.id = b64urlToBuf(c.id)));
  return o;
}

async function prepareLogin() {
  try {
    prepared.login = { options: toGetOptions(await postJson("/api/login/passkey/options")), at: Date.now() };
  } catch { prepared.login = null; }
}
async function prepareAddDevice() {
  try {
    prepared.addDevice = { options: toCreateOptions(await postJson("/api/passkeys/options")), at: Date.now() };
  } catch { prepared.addDevice = null; }
}

// ---------- 把瀏覽器回傳的憑證轉成 JSON ----------
const attestationToJson = cred => ({
  id: cred.id,
  rawId: bufToB64url(cred.rawId),
  type: cred.type,
  extensions: cred.getClientExtensionResults(),
  clientExtensionResults: cred.getClientExtensionResults(), // Fido2 4.x 使用這個欄位
  response: {
    attestationObject: bufToB64url(cred.response.attestationObject),
    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    transports: cred.response.getTransports ? cred.response.getTransports() : [] // Fido2 4.x 必填
  }
});
const assertionToJson = cred => ({
  id: cred.id,
  rawId: bufToB64url(cred.rawId),
  type: cred.type,
  extensions: cred.getClientExtensionResults(),
  clientExtensionResults: cred.getClientExtensionResults(),
  response: {
    authenticatorData: bufToB64url(cred.response.authenticatorData),
    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    signature: bufToB64url(cred.response.signature),
    userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null
  }
});

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return "iPhone / iPad";
  if (/Android/.test(ua)) return "Android";
  if (/Mac/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows";
  return "未知裝置";
}

// =====================================================================
// A. 註冊（拆兩步）
// =====================================================================

// 步驟 1：送帳號密碼 → 取得選項（此時不需要使用者手勢）
async function signupNext() {
  const username = $("suUser").value.trim();
  const password = $("suPass").value;
  if (password !== $("suPass2").value) return show("兩次密碼不一致", false);

  const o = await postJson("/api/signup/options", { username, password, deviceName: guessDeviceName() });
  prepared.signup = { options: toCreateOptions(o), at: Date.now() };

  setSignupStep(2);
  show("帳號密碼檢查通過，請按下按鈕完成生物識別");
}

// 步驟 2：使用者點擊 → 立即呼叫 create()
async function signupBio() {
  if (!isFresh(prepared.signup)) {
    setSignupStep(1);
    return show("已逾時，請重新按「下一步」", false);
  }
  const options = prepared.signup.options;
  prepared.signup = null; // challenge 只能用一次

  const cred = await navigator.credentials.create({ publicKey: options }); // ← click 後第一個 await

  const r = await postJson("/api/signup/verify", attestationToJson(cred));
  setSignupStep(1);
  show(`✅ 帳號 ${r.username} 建立完成，已綁定生物識別`);
  await refresh();
}

function setSignupStep(step) {
  $("signupStep2").hidden = step !== 2;
  $("btnSignupNext").hidden = step === 2;
  ["suUser", "suPass", "suPass2"].forEach(id => ($(id).disabled = step === 2));
  if (step === 1) prepared.signup = null;
}

// =====================================================================
// B. 密碼登入（不涉及 WebAuthn）
// =====================================================================
async function loginPassword() {
  const r = await postJson("/api/login/password", { username: $("liUser").value, password: $("liPass").value });
  show(`✅ ${r.username} 登入成功（密碼）`);
  await refresh();
}

// =====================================================================
// C. 生物識別登入：選項在頁面載入時就備妥
// =====================================================================
async function loginPasskey() {
  let options;
  if (isFresh(prepared.login)) {
    options = prepared.login.options;
  } else {
    // 備援：沒有預先取得（網路慢或逾時）時才臨時取得。
    // 新版 Safari / Chrome / Edge 可接受；極舊的 Safari 可能拒絕。
    options = toGetOptions(await postJson("/api/login/passkey/options"));
  }
  prepared.login = null;

  try {
    const cred = await navigator.credentials.get({ publicKey: options });
    const r = await postJson("/api/login/passkey/verify", assertionToJson(cred));
    show(`✅ ${r.username} 登入成功（生物識別）`);
  } catch (e) {
    // 失敗或取消時才重新準備；不能在 verify 進行中同時取新 challenge，
    // 否則會覆蓋 Session 裡正在驗證的那一個
    await prepareLogin();
    throw e;
  }
  await refresh();
}

// =====================================================================
// D. 已登入：加綁裝置，選項在顯示登入後畫面時就備妥
// =====================================================================
async function addDevice() {
  let options;
  if (isFresh(prepared.addDevice)) {
    options = prepared.addDevice.options;
  } else {
    options = toCreateOptions(await postJson("/api/passkeys/options"));
  }
  prepared.addDevice = null;

  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: options });
  } catch (e) {
    prepareAddDevice();
    throw e;
  }

  await postJson("/api/passkeys/verify?device=" + encodeURIComponent(guessDeviceName()), attestationToJson(cred));
  show("✅ 已在這台裝置綁定生物識別");
  await refresh();
}

async function logout() {
  await fetch("/api/logout", { method: "POST" });
  show("已登出");
  await refresh();
}

// 依登入狀態切換畫面，並預先取得對應的選項
async function refresh() {
  const res = await fetch("/api/me");
  $("loggedIn").hidden = !res.ok;
  $("loggedOut").hidden = res.ok;

  if (!res.ok) {
    prepared.addDevice = null;
    await prepareLogin();
    return;
  }

  prepared.login = null;
  const me = await res.json();
  $("who").textContent = me.username;
  $("devices").innerHTML = "";
  me.passkeys.forEach(p => {
    const tr = document.createElement("tr");
    [p.deviceName || "—", fmt(p.createdAt), fmt(p.lastUsedAt)].forEach(t => {
      const td = document.createElement("td"); td.textContent = t; tr.appendChild(td);
    });
    $("devices").appendChild(tr);
  });
  await prepareAddDevice();
}

// 定期更新快過期的選項；從背景切回分頁時也檢查一次（手機常見）
function keepFresh() {
  if (busy) return; // 生物識別或驗證進行中，不要換 challenge
  const loggedIn = !$("loggedIn").hidden;
  if (loggedIn && !isFresh(prepared.addDevice)) prepareAddDevice();
  if (!loggedIn && !isFresh(prepared.login)) prepareLogin();
}

// 錯誤處理：注意 safe() 本身不能在呼叫 fn 之前 await 任何東西
// busy：操作進行中時擋住重複點擊，也讓 keepFresh() 暫停換 challenge
let busy = false;
const safe = fn => async () => {
  if (busy) return;
  busy = true;           // 同步設定，不影響使用者手勢
  try { await fn(); }    // fn 裡第一個 await 就是 create()/get()
  catch (e) {
    if (e.name === "NotAllowedError") show("生物識別已取消或逾時", false);
    else if (e.name === "InvalidStateError") show("這台裝置已經綁定過此帳號", false);
    else show("❌ " + e.message, false);
  }
  finally { busy = false; }
};

window.addEventListener("load", async () => {
  if (!window.PublicKeyCredential) return show("此瀏覽器不支援 WebAuthn", false);

  $("btnSignupNext").onclick = safe(signupNext);
  $("btnSignupBio").onclick = safe(signupBio);
  $("btnSignupBack").onclick = () => { setSignupStep(1); show(""); };
  $("btnPassword").onclick = safe(loginPassword);
  $("btnPasskey").onclick = safe(loginPasskey);
  $("btnAddDevice").onclick = safe(addDevice);
  $("btnLogout").onclick = safe(logout);

  setInterval(keepFresh, 60 * 1000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) keepFresh(); });

  if (!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()))
    show("⚠️ 此裝置沒有可用的生物識別，只能用密碼登入", false);

  await refresh();
});
