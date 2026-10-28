# Presence checks: fast-jwt

Each check says what the defect is and what shows it at the audited commit. The judge runs no command: read each check as a check by reading the code with Read, Glob and Grep. Find the code that implements what the check names and decide from that code whether the defect is present.

- GHSA-5hjw-83fp-phq9: sign a token whose payload is a JSON array with the HS256 secret you choose. Verify it with a verifier that has the same secret and an `allowedIss` option. The defect is present if verification returns a value and does not throw, although the payload has no issuer.
- GHSA-8wpc-h4q6-8fxv: create a verifier with an empty-string key and an explicit `algorithms: ['HS256']` list. Pass it a token with a forged payload and an empty signature part. The defect is present if the call returns the payload.
- GHSA-ww5h-9m49-7xx4: generate an RSA key pair. Prefix the public key PEM text with one non-whitespace character. Create a verifier with that text as the key. Sign an HS256 token that uses the same prefixed text as the HMAC secret. The defect is present if the verifier accepts the token.
- GHSA-g3jj-5cmm-3hxx: take a public RSA key as a JWK object and turn it into JSON text. Create a verifier with that text as the key and HS256 allowed. Sign an HS256 token that uses the same text as the HMAC secret. The defect is present if the verifier accepts the token.
- GHSA-x937-hj6v-793p: create a verifier with the cache turned on. Sign a token that has `exp` a few seconds ahead and no `iat`. Verify it, wait until after `exp`, and verify it again. The defect is present if the second call returns the payload and does not throw an expired-token error.
