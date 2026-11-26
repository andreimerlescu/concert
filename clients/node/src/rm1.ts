import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

export const RM1_PREFIX = "rm1";
export const HEADER_ROOM_PASS = "X-Room-Pass";
export const HEADER_ROOM_LEASE = "X-Room-Lease";

export const RM1_MIN_TTL_SECONDS = 1;
export const RM1_DEFAULT_MAX_TTL_SECONDS = 15 * 60;
export const RM1_MAX_TTL_SECONDS = 60 * 60;
export const RM1_DEFAULT_CLOCK_SKEW_SECONDS = 30;
export const RM1_MAX_CLOCK_SKEW_SECONDS = 5 * 60;
export const RM1_MAX_TOKEN_LEN = 2048;
export const RM1_MAX_SCOPE_LEN = 256;
export const RM1_MAX_KEY_ID_LEN = 64;
export const RM1_MAX_KEY_LEN = 256;

export type RM1TokenKind = "pass" | "lease";

export interface RM1Claims {
  kid: string;
  kind: RM1TokenKind;
  scope: string;
  key?: string;
  iat: number;
  exp: number;
}

export interface RM1VerifyOptions {
  scope: string;
  kind?: RM1TokenKind;
  key?: string;
  nowSeconds?: number;
  maxClockSkewSeconds?: number;
}

export type RM1ErrorCode =
  | "invalid_key"
  | "invalid_claims"
  | "malformed"
  | "unknown_key"
  | "invalid_signature"
  | "wrong_scope"
  | "wrong_kind"
  | "key_mismatch"
  | "future_issued"
  | "expired";

export class RM1Error extends Error {
  readonly code: RM1ErrorCode;

  constructor(code: RM1ErrorCode, message: string) {
    super(message);
    this.name = "RM1Error";
    this.code = code;
  }
}

export type Ed25519PrivateKeyInput = KeyObject | string | Uint8Array;
export type Ed25519PublicKeyInput = KeyObject | string | Uint8Array;

// ASN.1 DER prefixes for RFC 8410 Ed25519 keys.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const STRICT_BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ALLOWED_CLAIM_KEYS = new Set(["kid", "kind", "scope", "key", "iat", "exp"]);

function toPrivateKeyObject(input: Ed25519PrivateKeyInput): KeyObject {
  try {
    if (typeof input === "string") {
      const trimmed = input.trim();
      if (trimmed.includes("BEGIN")) {
        const keyObj = createPrivateKey(trimmed);
        if (keyObj.asymmetricKeyType !== "ed25519") {
          throw new RM1Error("invalid_key", "private key must be Ed25519");
        }
        return keyObj;
      }
      const raw = decodeRawKeyBytes(trimmed);
      return rawPrivateBytesToKeyObject(raw);
    }
    if (input instanceof Uint8Array) {
      return rawPrivateBytesToKeyObject(input);
    }
    if (input.type !== "private" || input.asymmetricKeyType !== "ed25519") {
      throw new RM1Error("invalid_key", "private key KeyObject must be Ed25519");
    }
    return input;
  } catch (err) {
    if (err instanceof RM1Error) {
      throw err;
    }
    throw new RM1Error("invalid_key", "invalid Ed25519 private key");
  }
}

function rawPrivateBytesToKeyObject(raw: Uint8Array): KeyObject {
  // Accept either a 32-byte Ed25519 seed or a 64-byte Go-style seed||pubkey.
  let seed: Uint8Array;
  if (raw.byteLength === 32) {
    seed = raw;
  } else if (raw.byteLength === 64) {
    seed = raw.subarray(0, 32);
  } else {
    throw new RM1Error(
      "invalid_key",
      `Ed25519 private key bytes must be 32 (seed) or 64 (seed+pub), got ${raw.byteLength}`,
    );
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/**
 * Decodes an Ed25519 public key from KeyObject, PEM, raw 32-byte Uint8Array,
 * base64url, base64, or 64-char hex (matching Concert's -room-verify-keys).
 */
export function decodeEd25519PublicKey(input: Ed25519PublicKeyInput): KeyObject {
  try {
    if (typeof input === "string") {
      const trimmed = input.trim();
      if (trimmed.includes("BEGIN")) {
        const keyObj = createPublicKey(trimmed);
        if (keyObj.asymmetricKeyType !== "ed25519") {
          throw new RM1Error("invalid_key", "public key must be Ed25519");
        }
        return keyObj;
      }
      const raw = decodeRawKeyBytes(trimmed);
      return rawPublicBytesToKeyObject(raw);
    }
    if (input instanceof Uint8Array) {
      return rawPublicBytesToKeyObject(input);
    }
    if (input.type !== "public" || input.asymmetricKeyType !== "ed25519") {
      throw new RM1Error("invalid_key", "public key KeyObject must be Ed25519");
    }
    return input;
  } catch (err) {
    if (err instanceof RM1Error) {
      throw err;
    }
    throw new RM1Error("invalid_key", "invalid Ed25519 public key");
  }
}

function rawPublicBytesToKeyObject(raw: Uint8Array): KeyObject {
  if (raw.byteLength !== 32) {
    throw new RM1Error("invalid_key", `Ed25519 public key must be 32 bytes, got ${raw.byteLength}`);
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Exports a 32-byte raw Ed25519 public key from a KeyObject or encoded input.
 */
export function exportRawEd25519PublicKey(input: Ed25519PublicKeyInput): Buffer {
  const keyObj = decodeEd25519PublicKey(input);
  const spki = keyObj.export({ format: "der", type: "spki" });
  if (spki.byteLength !== ED25519_SPKI_PREFIX.byteLength + 32) {
    throw new RM1Error("invalid_key", "unexpected Ed25519 SPKI DER length");
  }
  return Buffer.from(spki.subarray(ED25519_SPKI_PREFIX.byteLength));
}

/**
 * Formats a map of kid -> Ed25519 public key into a deterministic
 * comma-separated spec for Concert's -room-verify-keys / CONCERT_ROOM_VERIFY_KEYS.
 */
export function formatVerifyKeysFlag(keys: Record<string, Ed25519PublicKeyInput>): string {
  const kids = Object.keys(keys).sort();
  if (kids.length === 0) {
    throw new RM1Error("invalid_key", "at least one public key is required");
  }
  return kids
    .map((kid) => {
      validateKeyID(kid);
      if (kid.includes(",") || kid.includes("=")) {
        throw new RM1Error("invalid_key", `key id ${JSON.stringify(kid)} must not contain ',' or '='`);
      }
      const raw = exportRawEd25519PublicKey(keys[kid]);
      return `${kid}=${raw.toString("base64url")}`;
    })
    .join(",");
}

function decodeRawKeyBytes(encoded: string): Buffer {
  if (/^[0-9a-fA-F]{64}$/.test(encoded) || /^[0-9a-fA-F]{128}$/.test(encoded)) {
    return Buffer.from(encoded, "hex");
  }
  if (/^[A-Za-z0-9_-]+=*$/.test(encoded)) {
    return Buffer.from(encoded.replace(/=+$/, ""), "base64url");
  }
  if (/^[A-Za-z0-9+/]+=*$/.test(encoded)) {
    return Buffer.from(encoded, "base64");
  }
  throw new RM1Error("invalid_key", "unrecognized key encoding");
}

function validateKeyID(kid: string): void {
  if (kid.length === 0 || Buffer.byteLength(kid, "utf8") > RM1_MAX_KEY_ID_LEN) {
    throw new RM1Error("invalid_key", `key id must be 1..${RM1_MAX_KEY_ID_LEN} bytes`);
  }
}

function validateClaimsForSign(claims: RM1Claims): void {
  validateKeyID(claims.kid);
  if (claims.kind !== "pass" && claims.kind !== "lease") {
    throw new RM1Error("invalid_claims", `unsupported rm1 kind ${JSON.stringify(claims.kind)}`);
  }
  if (claims.scope.length === 0 || Buffer.byteLength(claims.scope, "utf8") > RM1_MAX_SCOPE_LEN) {
    throw new RM1Error("invalid_claims", `scope must be 1..${RM1_MAX_SCOPE_LEN} bytes`);
  }
  if (claims.kind === "lease" && (!claims.key || claims.key.length === 0)) {
    throw new RM1Error("invalid_claims", "lease claims require non-empty key");
  }
  if (claims.key !== undefined && Buffer.byteLength(claims.key, "utf8") > RM1_MAX_KEY_LEN) {
    throw new RM1Error("invalid_claims", `key exceeds ${RM1_MAX_KEY_LEN} bytes`);
  }
  if (!Number.isSafeInteger(claims.iat) || claims.iat <= 0) {
    throw new RM1Error("invalid_claims", "iat must be a positive integer unix timestamp");
  }
  if (!Number.isSafeInteger(claims.exp) || claims.exp <= claims.iat) {
    throw new RM1Error("invalid_claims", "exp must be greater than iat");
  }
  const ttl = claims.exp - claims.iat;
  if (ttl < RM1_MIN_TTL_SECONDS || ttl > RM1_MAX_TTL_SECONDS) {
    throw new RM1Error(
      "invalid_claims",
      `token lifetime ${ttl}s must be within [${RM1_MIN_TTL_SECONDS}s, ${RM1_MAX_TTL_SECONDS}s]`,
    );
  }
}

/**
 * Signs an rm1 Ed25519 envelope wire-compatible with Concert and
 * github.com/andreimerlescu/room v1.8+.
 */
export function signRM1(privateKey: Ed25519PrivateKeyInput, claims: RM1Claims): string {
  const keyObj = toPrivateKeyObject(privateKey);
  validateClaimsForSign(claims);

  const wireClaims: Record<string, string | number> = {
    kid: claims.kid,
    kind: claims.kind,
    scope: claims.scope,
  };
  if (claims.key !== undefined && claims.key !== "") {
    wireClaims.key = claims.key;
  }
  wireClaims.iat = claims.iat;
  wireClaims.exp = claims.exp;

  const payloadB64 = Buffer.from(JSON.stringify(wireClaims), "utf8").toString("base64url");
  const signingInput = `${RM1_PREFIX}.${payloadB64}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, "utf8"), keyObj);
  const token = `${signingInput}.${sig.toString("base64url")}`;
  if (token.length > RM1_MAX_TOKEN_LEN) {
    throw new RM1Error("invalid_claims", `encoded token exceeds ${RM1_MAX_TOKEN_LEN} bytes`);
  }
  return token;
}

/**
 * Mints a short-lived rm1 VIP pass token using the current UTC timestamp.
 */
export function mintRM1Pass(
  privateKey: Ed25519PrivateKeyInput,
  keyID: string,
  scope: string,
  key = "",
  ttlSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): string {
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < RM1_MIN_TTL_SECONDS || ttlSeconds > RM1_MAX_TTL_SECONDS) {
    throw new RM1Error("invalid_claims", `ttlSeconds must be an integer in [${RM1_MIN_TTL_SECONDS}, ${RM1_MAX_TTL_SECONDS}]`);
  }
  const claims: RM1Claims = {
    kid: keyID,
    kind: "pass",
    scope,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
  };
  if (key !== "") {
    claims.key = key;
  }
  return signRM1(privateKey, claims);
}

/**
 * Mints a short-lived rm1 lease token bound to a non-empty client key.
 */
export function mintRM1Lease(
  privateKey: Ed25519PrivateKeyInput,
  keyID: string,
  scope: string,
  key: string,
  ttlSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): string {
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < RM1_MIN_TTL_SECONDS || ttlSeconds > RM1_MAX_TTL_SECONDS) {
    throw new RM1Error("invalid_claims", `ttlSeconds must be an integer in [${RM1_MIN_TTL_SECONDS}, ${RM1_MAX_TTL_SECONDS}]`);
  }
  return signRM1(privateKey, {
    kid: keyID,
    kind: "lease",
    scope,
    key,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
  });
}

function decodeStrictBase64URL(segment: string): Buffer {
  if (segment.length === 0 || !STRICT_BASE64URL_RE.test(segment)) {
    throw new RM1Error("malformed", "invalid base64url segment");
  }
  const buf = Buffer.from(segment, "base64url");
  // Reject non-canonical trailing bits by verifying round-trip encoding.
  if (buf.toString("base64url") !== segment) {
    throw new RM1Error("malformed", "non-canonical base64url encoding");
  }
  return buf;
}

/**
 * Verifies an rm1 token in strict security-first order:
 * 1. Preconditions (scope, key map).
 * 2. Length bound, framing, strict base64url, strict JSON decode.
 * 3. Ed25519 signature check FIRST (so forged tokens never appear as expired).
 * 4. Scope, kind, and key binding checks.
 * 5. Clock skew (iat) and expiry (exp) checks.
 */
export function verifyRM1(
  token: string,
  publicKeys: Record<string, Ed25519PublicKeyInput>,
  options: RM1VerifyOptions,
): RM1Claims {
  if (!options.scope || Buffer.byteLength(options.scope, "utf8") > RM1_MAX_SCOPE_LEN) {
    throw new RM1Error("invalid_claims", `verification scope must be 1..${RM1_MAX_SCOPE_LEN} bytes`);
  }
  const expectedKind: RM1TokenKind = options.kind ?? "pass";
  if (expectedKind !== "pass" && expectedKind !== "lease") {
    throw new RM1Error("invalid_claims", `unsupported expected kind ${JSON.stringify(expectedKind)}`);
  }
  if (Object.keys(publicKeys).length === 0) {
    throw new RM1Error("invalid_key", "at least one verification public key is required");
  }
  if (typeof token !== "string" || token.length === 0 || token.length > RM1_MAX_TOKEN_LEN) {
    throw new RM1Error("malformed", "token is empty or exceeds maximum length");
  }

  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== RM1_PREFIX || parts[1].length === 0 || parts[2].length === 0) {
    throw new RM1Error("malformed", "invalid rm1 token framing");
  }

  const payloadBuf = decodeStrictBase64URL(parts[1]);
  const sigBuf = decodeStrictBase64URL(parts[2]);
  if (sigBuf.byteLength !== 64) {
    throw new RM1Error("malformed", "Ed25519 signature must be 64 bytes");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBuf.toString("utf8"));
  } catch {
    throw new RM1Error("malformed", "invalid JSON payload");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RM1Error("malformed", "claims payload must be a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  for (const field of Object.keys(obj)) {
    if (!ALLOWED_CLAIM_KEYS.has(field)) {
      throw new RM1Error("malformed", `unknown claim field ${JSON.stringify(field)}`);
    }
  }
  if (
    typeof obj.kid !== "string" ||
    obj.kid.length === 0 ||
    Buffer.byteLength(obj.kid, "utf8") > RM1_MAX_KEY_ID_LEN ||
    (obj.kind !== "pass" && obj.kind !== "lease") ||
    typeof obj.scope !== "string" ||
    obj.scope.length === 0 ||
    Buffer.byteLength(obj.scope, "utf8") > RM1_MAX_SCOPE_LEN ||
    (obj.key !== undefined && typeof obj.key !== "string") ||
    typeof obj.iat !== "number" ||
    !Number.isSafeInteger(obj.iat) ||
    obj.iat <= 0 ||
    typeof obj.exp !== "number" ||
    !Number.isSafeInteger(obj.exp) ||
    obj.exp <= obj.iat
  ) {
    throw new RM1Error("malformed", "invalid rm1 claim fields");
  }

  // Verify cryptographic signature BEFORE checking scope/kind/expiry so
  // forged tokens never masquerade as expired tokens.
  if (!Object.prototype.hasOwnProperty.call(publicKeys, obj.kid)) {
    throw new RM1Error("unknown_key", `unknown rm1 key id ${JSON.stringify(obj.kid)}`);
  }
  const pubKeyObj = decodeEd25519PublicKey(publicKeys[obj.kid]);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const validSig = cryptoVerify(null, Buffer.from(signingInput, "utf8"), pubKeyObj, sigBuf);
  if (!validSig) {
    throw new RM1Error("invalid_signature", "invalid Ed25519 signature");
  }

  if (obj.scope !== options.scope) {
    throw new RM1Error("wrong_scope", `scope mismatch: got ${JSON.stringify(obj.scope)}`);
  }
  if (obj.kind !== expectedKind) {
    throw new RM1Error("wrong_kind", `kind mismatch: got ${JSON.stringify(obj.kind)}`);
  }
  const claimKey = typeof obj.key === "string" ? obj.key : "";
  const expectedKey = options.key ?? "";
  if (expectedKind === "lease") {
    if (claimKey === "") {
      throw new RM1Error("malformed", "lease token missing key claim");
    }
    if (claimKey !== expectedKey) {
      throw new RM1Error("key_mismatch", "lease key mismatch");
    }
  } else if (claimKey !== "" && claimKey !== expectedKey) {
    throw new RM1Error("key_mismatch", "pass key mismatch");
  }

  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const rawSkew = options.maxClockSkewSeconds ?? RM1_DEFAULT_CLOCK_SKEW_SECONDS;
  const skew = Math.min(RM1_MAX_CLOCK_SKEW_SECONDS, Math.max(0, rawSkew));
  if (obj.iat > now + skew) {
    throw new RM1Error("future_issued", "token issued in the future");
  }
  if (now >= obj.exp) {
    throw new RM1Error("expired", "token expired");
  }

  const verified: RM1Claims = {
    kid: obj.kid,
    kind: obj.kind,
    scope: obj.scope,
    iat: obj.iat,
    exp: obj.exp,
  };
  if (claimKey !== "") {
    verified.key = claimKey;
  }
  return verified;
}
