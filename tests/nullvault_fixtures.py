"""Test-only Android key attestation chains for NullVault (fake root; never trusted outside tests).

Builds root -> intermediate -> leaf with a hand-encoded KeyDescription extension
(1.3.6.1.4.1.11129.2.1.17), matching the layout KeyMint emits (attestation v200/300).
"""
import base64
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

KEY_DESC_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


# ---- minimal DER encoder ----
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def INT(v: int) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, "big", signed=True))


def ENUM(v: int) -> bytes:
    return tlv(0x0A, bytes([v]))


def BOOL(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def OCT(b: bytes) -> bytes:
    return tlv(0x04, b)


def SEQ(*items) -> bytes:
    return tlv(0x30, b"".join(items))


def SET(*items) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def NULL() -> bytes:
    return b"\x05\x00"


def CTX(tagnum: int, inner: bytes) -> bytes:
    """[tagnum] EXPLICIT, constructed context-specific; high-tag-number form above 30."""
    if tagnum < 31:
        head = bytes([0xA0 | tagnum])
    else:
        parts = []
        t = tagnum
        parts.append(t & 0x7F)
        t >>= 7
        while t:
            parts.append(0x80 | (t & 0x7F))
            t >>= 7
        head = bytes([0xBF]) + bytes(reversed(parts))
    return head + _len(len(inner)) + inner


def app_id(package: str, version: int, digests_hex) -> bytes:
    return SEQ(SET(SEQ(OCT(package.encode()), INT(version))),
               SET(*[OCT(bytes.fromhex(d)) for d in digests_hex]))


def key_description(challenge: bytes, *, sec=1, km_sec=None, boot_state=0, locked=True,
                    boot_key=b"\x11" * 32, patch=202610, package="cloud.nullverse.nullvault",
                    version=1, digests=("aa" * 32,), origin=0, model=None, manufacturer=None,
                    auth_timeout=None, no_auth=False) -> bytes:
    hw = [CTX(1, SET(INT(2))), CTX(2, INT(3)), CTX(3, INT(256)), CTX(10, INT(1))]
    if no_auth:
        hw.append(CTX(503, NULL()))
    hw += [CTX(504, INT(2))]
    if auth_timeout is not None:
        hw.append(CTX(505, INT(auth_timeout)))
    hw += [CTX(702, INT(origin)),
          CTX(704, SEQ(OCT(boot_key), BOOL(locked), ENUM(boot_state), OCT(b"\x22" * 32))),
          CTX(705, INT(150000)), CTX(706, INT(patch))]
    if manufacturer:
        hw.append(CTX(716, OCT(manufacturer.encode())))
    if model:
        hw.append(CTX(717, OCT(model.encode())))
    hw += [CTX(718, INT(patch * 100 + 5)), CTX(719, INT(patch * 100 + 5))]
    sw = [CTX(701, INT(1763000000000)), CTX(709, OCT(app_id(package, version, digests)))]
    return SEQ(INT(300), ENUM(sec), INT(300), ENUM(sec if km_sec is None else km_sec),
               OCT(challenge), OCT(b""), SEQ(*sw), SEQ(*hw))


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, signer, *, ca, ext=None, days=3650, not_before=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(not_before or now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(KEY_DESC_OID, ext), critical=False)
    return b.sign(signer, hashes.SHA256())


class FakeRoot:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = _cert("NullVault TEST root", "NullVault TEST root", self.key.public_key(), self.key, ca=True)
        self.ikey = ec.generate_private_key(ec.SECP256R1())
        self.icert = _cert("NullVault TEST intermediate", "NullVault TEST root", self.ikey.public_key(),
                           self.key, ca=True)

    def chain(self, leaf_pub, kd: bytes, *, ext_in_intermediate=False, sign_leaf_with=None,
              expired_intermediate=False):
        icert = self.icert
        if ext_in_intermediate or expired_intermediate:
            nb = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
                  if expired_intermediate else None)
            icert = _cert("NullVault TEST intermediate", "NullVault TEST root", self.ikey.public_key(),
                          self.key, ca=True, ext=kd if ext_in_intermediate else None,
                          days=-1 if expired_intermediate else 3650, not_before=nb)
        leaf = _cert("Android Keystore Key", "NullVault TEST intermediate", leaf_pub,
                     sign_leaf_with or self.ikey, ca=False, ext=kd)
        return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                for c in (leaf, icert, self.cert)], leaf


def sign(key, payload: bytes) -> str:
    return base64.b64encode(key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
