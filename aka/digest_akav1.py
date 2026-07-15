"""AKAv1-MD5 Digest helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets


@dataclass(frozen=True)
class DigestChallenge:
    realm: str
    nonce: str
    algorithm: str = "AKAv1-MD5"
    qop: str | None = None
    opaque: str | None = None


@dataclass(frozen=True)
class DigestCredentials:
    username: str
    realm: str
    uri: str
    method: str
    password: str | bytes
    nonce: str
    algorithm: str = "AKAv1-MD5"
    qop: str | None = None
    opaque: str | None = None
    cnonce: str = ""
    nc: str = "00000001"

    def with_cnonce(self) -> "DigestCredentials":
        if self.cnonce:
            return self
        return DigestCredentials(
            username=self.username,
            realm=self.realm,
            uri=self.uri,
            method=self.method,
            password=self.password,
            nonce=self.nonce,
            algorithm=self.algorithm,
            qop=self.qop,
            opaque=self.opaque,
            cnonce=secrets.token_hex(8),
            nc=self.nc,
        )


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def md5_hex_bytes(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()


def calculate_response(credentials: DigestCredentials) -> str:
    credentials = credentials.with_cnonce()
    if isinstance(credentials.password, bytes):
        ha1_source = (
            f"{credentials.username}:{credentials.realm}:".encode("utf-8") + credentials.password
        )
        ha1 = md5_hex_bytes(ha1_source)
    else:
        ha1 = md5_hex(f"{credentials.username}:{credentials.realm}:{credentials.password}")
    ha2 = md5_hex(f"{credentials.method}:{credentials.uri}")
    if credentials.qop:
        return md5_hex(
            f"{ha1}:{credentials.nonce}:{credentials.nc}:{credentials.cnonce}:{credentials.qop}:{ha2}"
        )
    return md5_hex(f"{ha1}:{credentials.nonce}:{ha2}")


def build_authorization(credentials: DigestCredentials) -> str:
    credentials = credentials.with_cnonce()
    response = calculate_response(credentials)
    params = [
        f'username="{credentials.username}"',
        f'realm="{credentials.realm}"',
        f'nonce="{credentials.nonce}"',
        f'uri="{credentials.uri}"',
        f'response="{response}"',
        f'algorithm={credentials.algorithm}',
    ]
    if credentials.opaque:
        params.append(f'opaque="{credentials.opaque}"')
    if credentials.qop:
        params.extend(
            [
                f"qop={credentials.qop}",
                f"nc={credentials.nc}",
                f'cnonce="{credentials.cnonce}"',
            ]
        )
    return "Digest " + ", ".join(params)
