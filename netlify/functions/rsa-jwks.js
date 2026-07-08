const {
  exportPublicJwk,
  getRsaKeyMetadata,
  getRsaPublicKeyPem,
  jsonResponse,
} = require("./_utils");

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return jsonResponse(204, {});
  }

  if (event.httpMethod !== "GET") {
    return jsonResponse(405, {
      error: "method_not_allowed",
      message: "Use GET for the RSA JWKS endpoint.",
    });
  }

  try {
    const { kid, alg, use } = getRsaKeyMetadata();
    const publicKeyPem = getRsaPublicKeyPem();
    const jwk = exportPublicJwk(publicKeyPem, "RSA");

    return jsonResponse(
      200,
      {
        keys: [
          {
            ...jwk,
            kid,
            alg,
            use,
          },
        ],
      },
      {
        "Cache-Control": "public, max-age=300",
      },
    );
  } catch (error) {
    return jsonResponse(500, {
      error: "rsa_jwks_configuration_error",
      message: error.message,
    });
  }
};