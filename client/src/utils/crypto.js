/**
 * ForenSight Client-Side Evidence Cryptography Subsystem
 *
 * Implements:
 *   1. Streaming SHA-256 computation over original artifact bytes.
 *   2. Cryptographically secure AES-256-GCM symmetric encryption with random 96-bit nonce.
 *   3. RSA-OAEP with SHA-256 for wrapping the generated AES key with the server's public key.
 *   4. Deterministic canonical message construction matching server lexicographical sorting.
 *   5. RSA-PSS with SHA-256 and 32-byte salt for uploader digital signatures.
 *
 * Utilizes the standard W3C Web Cryptography API (window.crypto.subtle) natively supported
 * in modern browsers.
 */

export function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function computeSha256(dataBuffer) {
  const digestBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
  return arrayBufferToHex(digestBuffer);
}

export function buildCanonicalSigningData({
  upload_id,
  original_sha256,
  filename,
  source_device,
  collector_id,
  timestamp,
  encryption_algorithm = 'AES-256-GCM',
  nonce_hex,
  tag_hex,
  encrypted_payload_sha256,
}) {
  const canonicalObj = {
    collector_id: (collector_id || '').trim(),
    encryption_algorithm: (encryption_algorithm || 'AES-256-GCM').trim(),
    encrypted_payload_sha256: (encrypted_payload_sha256 || '').trim().toLowerCase(),
    filename: (filename || '').trim(),
    nonce: (nonce_hex || '').trim().toLowerCase(),
    original_sha256: (original_sha256 || '').trim().toLowerCase(),
    source_device: (source_device || '').trim(),
    tag: (tag_hex || '').trim().toLowerCase(),
    timestamp: parseInt(timestamp, 10),
    upload_id: (upload_id || '').trim(),
  };

  const sortedKeys = Object.keys(canonicalObj).sort();
  const sortedObj = {};
  sortedKeys.forEach((key) => {
    sortedObj[key] = canonicalObj[key];
  });

  const canonicalString = JSON.stringify(sortedObj);
  return new TextEncoder().encode(canonicalString);
}

export async function encryptEvidencePayload(plaintextArrayBuffer) {
  // 1. Generate unique 256-bit AES key
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable for RSA-OAEP wrapping
    ['encrypt', 'decrypt']
  );
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

  // 2. Generate unique 12-byte (96-bit) cryptographically secure random nonce
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  // 3. Encrypt plaintext with AES-GCM (WebCrypto appends 16-byte authentication tag)
  const encryptedBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    plaintextArrayBuffer
  );

  const encryptedBytes = new Uint8Array(encryptedBuf);
  const tag = encryptedBytes.slice(encryptedBytes.length - 16);
  const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);

  // 4. ForenSight packaged container format: nonce (12) + tag (16) + ciphertext (N)
  const packaged = new Uint8Array(12 + 16 + ciphertext.length);
  packaged.set(nonce, 0);
  packaged.set(tag, 12);
  packaged.set(ciphertext, 28);

  const payloadSha256 = await computeSha256(packaged);

  return {
    rawAesKey,
    nonce,
    nonceHex: arrayBufferToHex(nonce.buffer),
    tag,
    tagHex: arrayBufferToHex(tag.buffer),
    packagedBytes: packaged,
    payloadSha256,
  };
}

export async function wrapAesKeyWithServerPublicKey(serverPublicKeyPem, rawAesKeyBuffer) {
  const spkiBuffer = pemToArrayBuffer(serverPublicKeyPem);
  const serverKey = await window.crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );

  const wrappedKeyBuffer = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    serverKey,
    rawAesKeyBuffer
  );

  return arrayBufferToHex(wrappedKeyBuffer);
}

export async function signCanonicalDataWithRsaPss(clientPrivateKeyPem, canonicalBytes) {
  const pkcs8Buffer = pemToArrayBuffer(clientPrivateKeyPem);
  const clientKey = await window.crypto.subtle.importKey(
    'pkcs8',
    pkcs8Buffer,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    clientKey,
    canonicalBytes
  );

  return arrayBufferToHex(signatureBuffer);
}

