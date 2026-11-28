"""step-ca one-time tokens (OTT) for SSH host certificates, signed by our own JWK.

The enroller holds the private key of a step-ca JWK provisioner (P-256, ES256),
derived from a seed. Only the public key goes into step-ca's ca.json, so the
private key never leaves the enroller. The token has the shape ``step ca token --ssh --host`` makes:

    header  {"alg": "ES256", "kid": <JWK thumbprint>, "typ": "JWT"}
    claims  iss = provisioner name, sub = key ID, aud = <ca>/1.0/ssh/sign,
            nbf/iat/exp (5 minutes), jti (random), sha = root fingerprint,
            step.ssh = {certType: host, keyID, principals, validAfter, validBefore}
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TOKEN_SECONDS = 300


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SigningKey:
    def __init__(self, key: ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("the provisioner key must be P-256")
        self._key = key

    @classmethod
    def from_seed(cls, seed: str) -> SigningKey:
        """Derive the key from a secret seed (Infisical), so it needs no volume.

        The same seed always gives the same key, so the public key in step-ca's ca.json stays
        valid across restarts. A new seed is a new key: register its public key again.
        """
        raw = seed.encode()
        if len(raw) < 32:
            raise ValueError("ENROLL_KEY_SEED must have at least 32 characters")
        okm = HKDF(
            algorithm=hashes.SHA256(), length=48, salt=None, info=b"vigil-host-enroller/jwk/p256/v1"
        ).derive(raw)
        # 384 bits mod (n - 1), plus 1: uniform enough, and never 0.
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = int.from_bytes(okm, "big") % (n - 1) + 1
        return cls(ec.derive_private_key(scalar, ec.SECP256R1()))

    def public_jwk(self) -> dict[str, str]:
        nums = self._key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64(nums.x.to_bytes(32, "big")),
            "y": _b64(nums.y.to_bytes(32, "big")),
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid(),
        }

    def kid(self) -> str:
        """RFC 7638 thumbprint, as step uses for the key ID."""
        nums = self._key.public_key().public_numbers()
        canon = json.dumps(
            {
                "crv": "P-256",
                "kty": "EC",
                "x": _b64(nums.x.to_bytes(32, "big")),
                "y": _b64(nums.y.to_bytes(32, "big")),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return _b64(hashlib.sha256(canon.encode()).digest())

    def sign(self, claims: dict[str, Any]) -> str:
        header = {"alg": "ES256", "kid": self.kid(), "typ": "JWT"}
        signing_input = (
            _b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        der = self._key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return signing_input + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def host_token(
    key: SigningKey,
    *,
    provisioner: str,
    ca_url: str,
    fingerprint: str,
    subject: str,
    principals: list[str],
    now: float | None = None,
) -> str:
    now = int(now if now is not None else time.time())
    claims = {
        "iss": provisioner,
        "sub": subject,
        "aud": f"{ca_url.rstrip('/')}/1.0/ssh/sign",
        "nbf": now,
        "iat": now,
        "exp": now + TOKEN_SECONDS,
        "jti": secrets.token_hex(32),
        "sha": fingerprint.lower(),
        "step": {
            "ssh": {
                "certType": "host",
                "keyID": subject,
                "principals": principals,
                "validAfter": "",
                "validBefore": "",
            }
        },
    }
    return key.sign(claims)
