// // export async function generateKeyPair() {
// //   const keyPair = await window.crypto.subtle.generateKey(
// //     {
// //       name: "RSA-PSS",
// //       modulusLength: 2048,
// //       publicExponent: new Uint8Array([1, 0, 1]),
// //       hash: "SHA-256",
// //     },
// //     true,
// //     ["sign", "verify"]
// //   );

// //   return keyPair;
// // }


// // // Convert CryptoKey → PEM
// // function arrayBufferToBase64(buffer: ArrayBuffer) {
// //   let binary = "";
// //   const bytes = new Uint8Array(buffer);
// //   bytes.forEach(b => (binary += String.fromCharCode(b)));
// //   return btoa(binary);
// // }

// // export async function exportPrivateKeyPEM(privateKey: CryptoKey) {
// //   const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
// //   const base64 = arrayBufferToBase64(pkcs8);

// //   return `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`;
// // }

// // export async function exportPublicKeyPEM(publicKey: CryptoKey) {
// //   const spki = await window.crypto.subtle.exportKey("spki", publicKey);
// //   const base64 = arrayBufferToBase64(spki);

// //   return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`;
// // }
// export async function generateKeyPair() {
//   return await window.crypto.subtle.generateKey(
//     {
//       name: "RSA-PSS",
//       modulusLength: 2048,
//       publicExponent: new Uint8Array([1, 0, 1]),
//       hash: "SHA-256",
//     },
//     true,
//     ["sign", "verify"]
//   );
// }

// export async function exportPublicKeyPEM(publicKey: CryptoKey) {
//   const spki = await window.crypto.subtle.exportKey("spki", publicKey);
//   const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));

//   return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`;
// }

// export async function exportPrivateKeyPEM(privateKey: CryptoKey) {
//   const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
//   const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));

//   return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`;
// }

// utils/keygen.ts

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function formatPEM(b64: string, type: string): string {
  const lines = b64.match(/.{1,64}/g)?.join("\n");
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  const t0 = performance.now();
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const keyGenTime = performance.now() - t0;
  console.log(`[METRIC] Key Generation: ${keyGenTime.toFixed(2)} ms`);

  return keyPair;
}

export async function exportPublicKeyPEM(publicKey: CryptoKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  return formatPEM(arrayBufferToBase64(spki), "PUBLIC KEY");
}

export async function exportPrivateKeyPEM(privateKey: CryptoKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return formatPEM(arrayBufferToBase64(pkcs8), "PRIVATE KEY");
}
