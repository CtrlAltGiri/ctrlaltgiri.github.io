#!/usr/bin/env node
// Encrypt a plaintext HTML file into _data/vault.json using AES-GCM with a
// PBKDF2-derived key. The plaintext is never committed; only the ciphertext is.
//
// Usage:
//   VAULT_PASSWORD=newtaste node scripts/encrypt.js
//   node scripts/encrypt.js <password> [inputFile] [outputFile]
//
// Defaults: input _secret/taste.src.html, output _data/vault.json
// The crypto parameters here must match the browser decryption logic.

const fs = require("fs");
const path = require("path");
const { webcrypto } = require("crypto");
const { subtle } = webcrypto;

const PBKDF2_ITERATIONS = 250000;

async function deriveKey(password, salt) {
  const keyMaterial = await subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

async function main() {
  const password = process.env.VAULT_PASSWORD || process.argv[2];
  const inputFile = process.argv[3] || "_secret/taste.src.html";
  const outputFile = process.argv[4] || "_data/vault.json";

  if (!password) {
    console.error("Missing password. Set VAULT_PASSWORD or pass it as the first argument.");
    process.exit(1);
  }

  const plaintext = fs.readFileSync(path.resolve(inputFile));
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  const payload = {
    v: 1,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: Buffer.from(salt).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    ct: Buffer.from(new Uint8Array(ciphertext)).toString("base64"),
  };

  fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
  fs.writeFileSync(path.resolve(outputFile), JSON.stringify(payload, null, 2) + "\n");
  console.log(`Encrypted ${inputFile} -> ${outputFile} (${payload.ct.length} b64 chars).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
