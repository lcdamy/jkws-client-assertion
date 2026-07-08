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

function normalizePem(value) {
  if (!value) {
    return "";
  }

  return value.trim().replace(/\\n/g, "\n");
}

function getPublicKeyPem() {
  const publicKeyPem = normalizePem(process.env.JWKS_PUBLIC_KEY_PEM);

  if (publicKeyPem) {
    return publicKeyPem;
  }

  const privateKeyPem = getPrivateKeyPem();
  return createPublicKey(privateKeyPem).export({ type: "spki", format: "pem" });
}

function getPrivateKeyPem() {
  const privateKeyPem = normalizePem(
    process.env.JWKS_PRIVATE_KEY_PEM || process.env.PRIVATE_KEY_PEM,
  );

  if (!privateKeyPem) {
    throw new Error("Missing JWKS_PRIVATE_KEY_PEM environment variable.");
  }

  return privateKeyPem;
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

module.exports = {
  base64Url,
  getKeyMetadata,
  getPrivateKeyPem,
  getPublicKeyPem,
  jsonResponse,
  normalizePem,
};
