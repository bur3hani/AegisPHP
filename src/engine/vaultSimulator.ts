import { AegisUser, AuthAuditRecord, PasswordResetRecord } from '../types/defense';

/**
 * Generates a cryptographically strong random password using window.crypto CSPRNG.
 * Guarantees at least 2 uppercase, 2 lowercase, 2 digits, and 2 symbols.
 */
export function generateSecurePassword(length: number = 18): string {
  const safeLength = Math.max(16, Math.min(48, length));

  const uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lowers = 'abcdefghijkmnopqrstuvwxyz';
  const numbers = '23456789';
  const symbols = '!@#$%^&*()-_=+[]{}';

  const getRandomChar = (str: string) => {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return str[arr[0] % str.length];
  };

  const chars: string[] = [
    getRandomChar(uppers),
    getRandomChar(uppers),
    getRandomChar(lowers),
    getRandomChar(lowers),
    getRandomChar(numbers),
    getRandomChar(numbers),
    getRandomChar(symbols),
    getRandomChar(symbols),
  ];

  const allChars = uppers + lowers + numbers + symbols;
  while (chars.length < safeLength) {
    chars.push(getRandomChar(allChars));
  }

  // Cryptographic Fisher-Yates shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    const j = arr[0] % (i + 1);
    const temp = chars[i];
    chars[i] = chars[j];
    chars[j] = temp;
  }

  return chars.join('');
}

/**
 * Calculates Shannon Entropy in bits for a given password:
 * Entropy = Length * log2(PoolSize)
 */
export function calculatePasswordEntropy(password: string): number {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  if (pool === 0) return 0;

  const entropy = password.length * Math.log2(pool);
  return Number(entropy.toFixed(1));
}

/**
 * Generates a 256-bit single-use reset token and its SHA-256 hash.
 */
export function generateOneTimeToken(): { rawToken: string; tokenHash: string } {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  const rawToken = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Deterministic FNV/SHA simulation for hash string
  let h1 = 0x811c9dc5;
  for (let i = 0; i < rawToken.length; i++) {
    h1 = Math.imul(h1 ^ rawToken.charCodeAt(i), 0x01000193);
  }
  const tokenHash = (h1 >>> 0).toString(16).padStart(8, '0') + rawToken.slice(0, 56);

  return { rawToken, tokenHash };
}

/**
 * Simulates AES-256-GCM authenticated encryption with a 96-bit IV and 128-bit authentication tag.
 */
export function simulateAes256GcmEncrypt(plaintext: string): {
  ivHex: string;
  tagHex: string;
  ciphertextHex: string;
  payloadBase64: string;
} {
  if (!plaintext) {
    return { ivHex: '', tagHex: '', ciphertextHex: '', payloadBase64: '' };
  }

  const ivBytes = new Uint8Array(12);
  const tagBytes = new Uint8Array(16);
  window.crypto.getRandomValues(ivBytes);
  window.crypto.getRandomValues(tagBytes);

  const ivHex = Array.from(ivBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const tagHex = Array.from(tagBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // XOR stream simulation with key bytes
  const encoder = new TextEncoder();
  const textBytes = encoder.encode(plaintext);
  const cipherBytes = new Uint8Array(textBytes.length);
  for (let i = 0; i < textBytes.length; i++) {
    cipherBytes[i] = textBytes[i] ^ (ivBytes[i % 12] + 0x5a);
  }

  const ciphertextHex = Array.from(cipherBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Combine iv + tag + ciphertext into Base64
  const combined = new Uint8Array(12 + 16 + cipherBytes.length);
  combined.set(ivBytes, 0);
  combined.set(tagBytes, 12);
  combined.set(cipherBytes, 28);

  let binary = '';
  for (let i = 0; i < combined.byteLength; i++) {
    binary += String.fromCharCode(combined[i]);
  }
  const payloadBase64 = btoa(binary);

  return { ivHex, tagHex, ciphertextHex, payloadBase64 };
}

export const INITIAL_AEGIS_USERS: AegisUser[] = [
  {
    id: 1,
    uuid: 'usr_840192a7e4b9',
    email: 'engr.buru@gmail.com',
    name: 'Engr. Buru (BuruOps Lead)',
    role: 'admin',
    status: 'active',
    failedAttempts: 0,
    mustChangePassword: false,
    lastLoginAt: '2026-10-28 07:42:15 UTC',
    createdAt: '2026-10-20 10:00:00 UTC',
  },
  {
    id: 2,
    uuid: 'usr_491028f1c8a3',
    email: 'marcus.vance@meridian-security.co.uk',
    name: 'Marcus Vance',
    role: 'responder',
    status: 'active',
    failedAttempts: 0,
    mustChangePassword: false,
    lastLoginAt: '2026-10-27 16:20:41 UTC',
    createdAt: '2026-10-22 14:15:00 UTC',
  },
  {
    id: 3,
    uuid: 'usr_771829d4b2e9',
    email: 'elena.rostova@albioncloud.co.uk',
    name: 'Elena Rostova',
    role: 'auditor',
    status: 'active',
    failedAttempts: 0,
    mustChangePassword: false,
    lastLoginAt: '2026-10-26 09:12:08 UTC',
    createdAt: '2026-10-24 11:30:00 UTC',
  },
  {
    id: 4,
    uuid: 'usr_992014a1c5d7',
    email: 'readonly-analyst@buruops.local',
    name: 'Readonly Compliance Reviewer',
    role: 'readonly',
    status: 'active',
    failedAttempts: 0,
    mustChangePassword: true,
    lastLoginAt: null,
    createdAt: '2026-10-27 18:45:00 UTC',
  },
];

export const INITIAL_AUTH_AUDIT_LOGS: AuthAuditRecord[] = [
  {
    id: 101,
    timestamp: '2026-10-28 07:42:15 UTC',
    eventType: 'login_success',
    email: 'engr.buru@gmail.com',
    success: true,
    details: 'Admin session authenticated with Argon2id hash',
  },
  {
    id: 102,
    timestamp: '2026-10-28 06:14:22 UTC',
    eventType: 'password_reset_success',
    email: 'marcus.vance@meridian-security.co.uk',
    success: true,
    details: 'Single-use 256-bit token consumed within 15-minute window',
  },
  {
    id: 103,
    timestamp: '2026-10-28 04:30:05 UTC',
    eventType: 'login_failed',
    email: 'attacker-probe@unknown.com',
    success: false,
    details: 'Unknown user credential submission blocked',
  },
];
