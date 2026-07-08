const { createPublicKey } = require("node:crypto");

function jsonResponse(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Assertion-Api-Key",
      ...extraHeaders,
    },
    body: JSON.stringify(body, null, 2),
  };
}

function normalizePem(value, name = "PEM") {
  if (!value) {
    throw new Error(`${name} is missing`);
  }

  return value
    .replace(/^["']|["']$/g, "")
    .replace(/\\n/g, "\n")
    .trim()
    .concat("\n");
}

function getPublicKeyPem() {
  const publicKeyPem = process.env.JWKS_PUBLIC_KEY_PEM;

  if (publicKeyPem) {
    return normalizePem(publicKeyPem, "JWKS_PUBLIC_KEY_PEM");
  }

  const privateKeyPem = getPrivateKeyPem();

  return createPublicKey(privateKeyPem).export({
    type: "spki",
    format: "pem",
  });
}

function getPrivateKeyPem() {
  return normalizePem(
    process.env.JWKS_PRIVATE_KEY_PEM || process.env.PRIVATE_KEY_PEM,
    "JWKS_PRIVATE_KEY_PEM",
  );
}

function base64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function getKeyMetadata() {
  return {
    kid: process.env.JWKS_KID || "u5aw0txey983f0i97zh8hbhtqpahhael",
    alg: process.env.JWKS_ALG || "ES384",
    use: process.env.JWKS_USE || "sig",
  };
}

function getRsaPublicKeyPem() {
  const publicKeyPem = process.env.RSA_JWKS_PUBLIC_KEY_PEM;

  if (publicKeyPem) {
    return normalizePem(publicKeyPem, "RSA_JWKS_PUBLIC_KEY_PEM");
  }

  const privateKeyPem = process.env.RSA_JWKS_PRIVATE_KEY_PEM;

  if (privateKeyPem) {
    return createPublicKey(
      normalizePem(privateKeyPem, "RSA_JWKS_PRIVATE_KEY_PEM"),
    ).export({
      type: "spki",
      format: "pem",
    });
  }

  throw new Error("Missing RSA_JWKS_PUBLIC_KEY_PEM environment variable.");
}

function exportPublicJwk(publicKeyPem, expectedKeyType) {
  const jwk = createPublicKey(publicKeyPem).export({ format: "jwk" });

  if (expectedKeyType && jwk.kty !== expectedKeyType) {
    throw new Error(
      `Invalid key type. Expected ${expectedKeyType}, but received ${jwk.kty}.`,
    );
  }

  return jwk;
}

function getRsaKeyMetadata() {
  return {
    kid: process.env.RSA_JWKS_KID || "client-encryption-rsa-001",
    alg: process.env.RSA_JWKS_ALG || "RSA-OAEP-256",
    use: process.env.RSA_JWKS_USE || "enc",
  };
}

module.exports = {
  base64Url,
  exportPublicJwk,
  getKeyMetadata,
  getPrivateKeyPem,
  getPublicKeyPem,
  getRsaKeyMetadata,
  getRsaPublicKeyPem,
  jsonResponse,
  normalizePem,
};
