const { randomUUID, sign } = require("node:crypto");
const {
  base64Url,
  getKeyMetadata,
  getPrivateKeyPem,
  jsonResponse,
} = require("./_utils");

function parseJsonBody(event) {
  if (!event.body) {
    return {};
  }

  const body = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;

  return JSON.parse(body);
}

function assertApiKey(event) {
  const expectedApiKey = process.env.ASSERTION_API_KEY;

  if (!expectedApiKey) {
    throw new Error("Missing ASSERTION_API_KEY environment variable. Refusing to expose client assertion generation without protection.");
  }

  const providedApiKey =
    event.headers["x-assertion-api-key"] ||
    event.headers["X-Assertion-Api-Key"];

  if (providedApiKey !== expectedApiKey) {
    const error = new Error("Invalid or missing X-Assertion-Api-Key header.");
    error.statusCode = 401;
    throw error;
  }
}

function buildClientAssertion({ clientId, audience, expiresInSeconds }) {
  const { kid, alg } = getKeyMetadata();

  if (alg !== "ES384") {
    throw new Error("This client assertion function currently supports ES384 only.");
  }

  const privateKeyPem = getPrivateKeyPem();
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = Number(expiresInSeconds || process.env.ASSERTION_EXPIRES_IN_SECONDS || 300);

  if (!clientId) {
    throw new Error("Missing clientId. Provide it in the request body or CLIENT_ID environment variable.");
  }

  if (!audience) {
    throw new Error("Missing audience. Provide it in the request body or TOKEN_ENDPOINT environment variable.");
  }

  if (!Number.isInteger(expirySeconds) || expirySeconds < 30 || expirySeconds > 604800) {
    throw new Error("expiresInSeconds must be an integer between 30 and 604800.");
  }

  const header = {
    typ: "JWT",
    alg,
    kid,
  };

  const payload = {
    iss: clientId,
    sub: clientId,
    aud: audience,
    iat: now,
    exp: now + expirySeconds,
    jti: randomUUID(),
  };

  const encodedHeader = base64Url(JSON.stringify(header));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = sign("sha384", Buffer.from(signingInput), {
    key: privateKeyPem,
    dsaEncoding: "ieee-p1363",
  });

  const token = `${signingInput}.${base64Url(signature)}`;

  return {
    client_assertion: token,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    header,
    payload,
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return jsonResponse(204, {});
  }

  if (event.httpMethod !== "POST") {
    return jsonResponse(405, {
      error: "method_not_allowed",
      message: "Use POST for client assertion generation.",
    });
  }

  try {
    assertApiKey(event);

    const body = parseJsonBody(event);
    const result = buildClientAssertion({
      clientId: body.clientId || process.env.CLIENT_ID,
      audience: body.audience || process.env.TOKEN_ENDPOINT,
      expiresInSeconds: body.expiresInSeconds,
    });

    return jsonResponse(200, result);
  } catch (error) {
    return jsonResponse(error.statusCode || 400, {
      error: error.statusCode === 401 ? "unauthorized" : "client_assertion_error",
      message: error.message,
    });
  }
};
