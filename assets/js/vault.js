// Client-side decryption for the encrypted "taste" page.
// Parameters must match scripts/encrypt.js exactly.
(function () {
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }

  async function deriveKey(password, salt, iterations) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  // Resolves to the decrypted plaintext string, or rejects if the password is
  // wrong (AES-GCM authentication fails).
  async function decrypt(password, payload) {
    const key = await deriveKey(password, b64ToBuf(payload.salt), payload.iterations);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(payload.iv) },
      key,
      b64ToBuf(payload.ct)
    );
    return new TextDecoder().decode(plaintext);
  }

  window.Vault = { decrypt: decrypt };
})();
