// const BASE = "http://127.0.0.1:5000";

// export const Api = {

//   /* 🔑 Register new user public key */
//   async registerUser(username: string, publicKey: string) {
//     const res = await fetch(`${BASE}/register`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, publicKey }),
//     });
//     return res.json();
//   },

//   /* 🔐 Get nonce challenge (POST — current active endpoint) */
//   async getLoginNonce(username: string) {
//     const res = await fetch(`${BASE}/challenge`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username }),
//     });
//     return res.json();
//   },

//   /* 🔐 Get challenge via legacy GET route (kept for backwards compatibility) */
//   async getChallenge(username: string) {
//     const res = await fetch(`${BASE}/challenge/${username}`);
//     return res.json();
//   },

//   /* 🔐 Verify login signature */
//   async verifyLogin(username: string, signature: string) {
//     const res = await fetch(`${BASE}/login`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, signature }),
//     });
//     return res.json();
//   },

//   /* 📜 Get audit logs */
//   async getLogs() {
//     const res = await fetch(`${BASE}/logs`);
//     return res.json();
//   },

//   /* 🔎 Verify audit log integrity */
//   async verifyLogIntegrity() {
//     const res = await fetch(`${BASE}/verify-logs`);
//     return res.json();
//   },

//   /* ⚙️ Get challenge for a sensitive operation */
//   async getOperationChallenge(username: string, operation: string, context: any) {
//     const res = await fetch(`${BASE}/operation-challenge`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, operation, context }),
//     });
//     return res.json();
//   },

//   /* ⚙️ Execute a sensitive operation (includes signature for server-side verification) */
//   async executeOperation(
//     username: string,
//     operation: string,
//     nonce: string,
//     context: any,
//     signature: string,
//   ) {
//     const res = await fetch(`${BASE}/execute-operation`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, operation, nonce, context, signature }),
//     });
//     return res.json();
//   },

//   /* 🪜 Get step-up authentication challenge */
//   async getStepUpChallenge(username: string, operation: string) {
//     const res = await fetch(`${BASE}/stepup-challenge`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, operation }),
//     });
//     return res.json();
//   },

//   /* 🪜 Verify step-up authentication signature */
//   async verifyStepUp(username: string, operation: string, signature: string) {
//     const res = await fetch(`${BASE}/stepup-verify`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, operation, signature }),
//     });
//     return res.json();
//   },
// };
const BASE = "http://127.0.0.1:5000";

export const Api = {

  /* 🔑 Register new user public key */
  async registerUser(username: string, publicKey: string) {
    const res = await fetch(`${BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, publicKey }),
    });
    return res.json();
  },

  /* 🔐 Get nonce challenge (POST — current active endpoint) */
  async getLoginNonce(username: string) {
    const res = await fetch(`${BASE}/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    return res.json();
  },

  /* 🔐 Get challenge via legacy GET route (kept for backwards compatibility) */
  async getChallenge(username: string) {
    const res = await fetch(`${BASE}/challenge/${username}`);
    return res.json();
  },

  /* 🔐 Verify login signature */
  async verifyLogin(username: string, signature: string) {
    const res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, signature }),
    });
    return res.json();
  },

  /* 📜 Get audit logs */
  async getLogs() {
    const res = await fetch(`${BASE}/logs`);
    return res.json();
  },

  /* 🔎 Verify audit log integrity */
  async verifyLogIntegrity() {
    const res = await fetch(`${BASE}/verify-logs`);
    return res.json();
  },

  /* ⚙️ Get challenge for a sensitive operation */
  async getOperationChallenge(username: string, operation: string, context: any) {
    const res = await fetch(`${BASE}/operation-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, context }),
    });
    return res.json();
  },

  /* ⚙️ Execute a sensitive operation (includes signature for server-side verification) */
  async executeOperation(
    username: string,
    operation: string,
    nonce: string,
    context: any,
    signature: string,          // required: Dashboard always signs before executing
  ) {
    const res = await fetch(`${BASE}/execute-operation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, nonce, context, signature }),
    });
    return res.json();
  },

  /* 🪜 Get step-up authentication challenge */
  async getStepUpChallenge(username: string, operation: string) {
    const res = await fetch(`${BASE}/stepup-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation }),
    });
    return res.json();
  },

  /* 🪜 Verify step-up authentication signature */
  async verifyStepUp(username: string, operation: string, nonce: string, signature: string) {
    const res = await fetch(`${BASE}/stepup-verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, nonce, signature }),
    });
    return res.json();
  },

  // ── Admin ──────────────────────────────────────────────────────────────────

  /* 🛡️ Admin password login — returns session token */
  async adminLogin(username: string, password: string) {
    const res = await fetch(`${BASE}/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    return res.json();   // { status, token }
  },

  /* 🛡️ Fetch full audit log (admin only) */
  async adminGetLogs(token: string) {
    const res = await fetch(`${BASE}/admin/logs`, {
      headers: { "X-Admin-Token": token },
    });
    return res.json();
  },

  /* 🛡️ Per-entry hash chain verification (admin only) */
  async adminVerifyChain(token: string) {
    const res = await fetch(`${BASE}/admin/verify-chain`, {
      headers: { "X-Admin-Token": token },
    });
    return res.json();   // { overall, entries: [...] }
  },

  /* 🛡️ Simulate DB tampering — corrupts one log entry (demo only) */
  async adminTamperLog(token: string, targetId?: number) {
    const res = await fetch(`${BASE}/admin/tamper-log`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Token": token,
      },
      body: JSON.stringify(targetId ? { target_id: targetId } : {}),
    });
    return res.json();   // { status, tampered_id }
  },

  /* 🛡️ Restore chain after tamper demo */
  async adminRestoreLogs(token: string) {
    const res = await fetch(`${BASE}/admin/restore-logs`, {
      method: "POST",
      headers: { "X-Admin-Token": token },
    });
    return res.json();   // { status: "RESTORED" }
  },
};