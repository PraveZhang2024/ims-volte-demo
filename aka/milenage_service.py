"""CryptoMobile-backed IMS AKA Milenage service."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hmac
import logging
from typing import Any

from app.errors import AkaError

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class AkaChallenge:
    rand: bytes
    autn: bytes

    @classmethod
    def from_nonce(cls, nonce: str) -> "AkaChallenge":
        try:
            raw = base64.b64decode(nonce + "=" * (-len(nonce) % 4), validate=False)
        except Exception as exc:
            raise AkaError("Unable to base64-decode AKA nonce") from exc
        if len(raw) < 32:
            raise AkaError(f"AKA nonce must contain RAND+AUTN, got {len(raw)} bytes")
        return cls(rand=raw[:16], autn=raw[16:32])

    @property
    def sqn_xor_ak(self) -> bytes:
        return self.autn[:6]

    @property
    def amf(self) -> bytes:
        return self.autn[6:8]

    @property
    def mac_a(self) -> bytes:
        return self.autn[8:16]


@dataclass(frozen=True)
class AkaResult:
    res: bytes
    ck: bytes
    ik: bytes
    ak: bytes
    sqn: bytes
    mac_verified: bool

    @property
    def res_hex(self) -> str:
        return self.res.hex()

    @property
    def ck_hex(self) -> str:
        return self.ck.hex()

    @property
    def ik_hex(self) -> str:
        return self.ik.hex()


class MilenageService:
    def __init__(self, k_hex: str, opc_hex: str) -> None:
        self.k = bytes.fromhex(k_hex)
        self.opc = bytes.fromhex(opc_hex)
        if len(self.k) != 16 or len(self.opc) != 16:
            raise AkaError("K and OPc must be 16-byte hex strings")

    def compute(self, challenge: AkaChallenge) -> AkaResult:
        milenage = self._new_milenage()
        res, ck, ik, ak = self._f2345(milenage, challenge.rand)
        sqn = bytes(a ^ b for a, b in zip(challenge.sqn_xor_ak, ak[:6]))
        computed_mac = self._f1(milenage, challenge.rand, sqn, challenge.amf)
        mac_verified = hmac.compare_digest(computed_mac[:8], challenge.mac_a)
        LOGGER.info("AKA MAC verification: %s", "ok" if mac_verified else "failed")
        return AkaResult(res=res, ck=ck, ik=ik, ak=ak, sqn=sqn, mac_verified=mac_verified)

    def _new_milenage(self) -> Any:
        try:
            from CryptoMobile.Milenage import Milenage  # type: ignore
        except Exception as exc:
            raise AkaError(
                "CryptoMobile is required for IMS AKA. Install it in the Linux lab "
                "environment and report the import/API if this adapter needs adjustment."
            ) from exc

        for args in ((self.opc,), ()):
            try:
                instance = Milenage(*args)
                break
            except TypeError:
                instance = None
        if instance is None:
            raise AkaError("Unable to instantiate CryptoMobile.Milenage")

        for setter_name in ("set_opc", "set_opc_bytes", "setOPc"):
            setter = getattr(instance, setter_name, None)
            if callable(setter):
                setter(self.opc)
                return instance

        if hasattr(instance, "OPc"):
            setattr(instance, "OPc", self.opc)
        return instance

    def _f2345(self, milenage: Any, rand: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        method = getattr(milenage, "f2345", None)
        if not callable(method):
            raise AkaError("CryptoMobile Milenage object has no f2345 method")
        try:
            values = method(self.k, rand)
        except TypeError:
            values = method(rand, self.k)
        if len(values) < 4:
            raise AkaError("CryptoMobile f2345 did not return RES, CK, IK, AK")
        return bytes(values[0]), bytes(values[1]), bytes(values[2]), bytes(values[3])

    def _f1(self, milenage: Any, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        method = getattr(milenage, "f1", None)
        if not callable(method):
            raise AkaError("CryptoMobile Milenage object has no f1 method")
        try:
            value = method(self.k, rand, sqn, amf)
        except TypeError:
            value = method(rand, sqn, amf, self.k)
        if isinstance(value, tuple):
            value = value[0]
        return bytes(value)
