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


@dataclass(frozen=True)
class DigestDebug:
    username: str
    realm: str
    uri: str
    method: str
    nonce: str
    algorithm: str
    qop: str | None
    nc: str
    cnonce: str
    opaque: str | None
    password_mode: str
    password_debug: str
    ha1_input_debug: str
    ha1: str
    ha2_input: str
    ha2: str
    response_input: str
    response: str


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def md5_hex_bytes(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()


def calculate_response(credentials: DigestCredentials) -> str:
    return digest_debug(credentials).response


def digest_debug(credentials: DigestCredentials) -> DigestDebug:
    credentials = credentials.with_cnonce()
    if isinstance(credentials.password, bytes):
        prefix = f"{credentials.username}:{credentials.realm}:".encode("utf-8")
        ha1_source = prefix + credentials.password
        ha1 = md5_hex_bytes(ha1_source)
        password_mode = "raw"
        password_debug = "0x" + credentials.password.hex()
        ha1_input_debug = prefix.decode("utf-8") + password_debug
    else:
        ha1_input_debug = f"{credentials.username}:{credentials.realm}:{credentials.password}"
        ha1 = md5_hex(ha1_input_debug)
        password_mode = "text"
        password_debug = credentials.password
    ha2_input = f"{credentials.method}:{credentials.uri}"
    ha2 = md5_hex(ha2_input)
    if credentials.qop:
        response_input = (
            f"{ha1}:{credentials.nonce}:{credentials.nc}:{credentials.cnonce}:{credentials.qop}:{ha2}"
        )
    else:
        response_input = f"{ha1}:{credentials.nonce}:{ha2}"
    response = md5_hex(response_input)
    return DigestDebug(
        username=credentials.username,
        realm=credentials.realm,
        uri=credentials.uri,
        method=credentials.method,
        nonce=credentials.nonce,
        algorithm=credentials.algorithm,
        qop=credentials.qop,
        nc=credentials.nc,
        cnonce=credentials.cnonce,
        opaque=credentials.opaque,
        password_mode=password_mode,
        password_debug=password_debug,
        ha1_input_debug=ha1_input_debug,
        ha1=ha1,
        ha2_input=ha2_input,
        ha2=ha2,
        response_input=response_input,
        response=response,
    )


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
