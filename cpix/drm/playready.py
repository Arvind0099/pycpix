"""
Functions for manipulating Playready DRM
"""
from base64 import b16decode, b16encode, b64decode, b64encode
import uuid
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from construct.core import Prefixed, Struct, Const, Int8ub, Int24ub, Int32ub, \
    Bytes, GreedyBytes, PrefixedArray, Default, If, this
from lxml import etree


PLAYREADY_SYSTEM_ID = uuid.UUID("9a04f079-9840-4286-ab92-e65be0885f95")

# Construct for a Playready PSSH box
pssh_box = Prefixed(
    Int32ub,
    Struct(
        "type" / Const(b"pssh"),
        "version" / Default(Int8ub, 1),
        "flags" / Const(0, Int24ub),
        "system_id" / Const(PLAYREADY_SYSTEM_ID.bytes, Bytes(16)),
        "key_ids" / If(this.version == 1, PrefixedArray(Int32ub, Bytes(16))),
        "data" / Prefixed(Int32ub, GreedyBytes)
    ),
    includelength=True
)


def generate_content_key(key_id, key_seed):
    """
    Generate content key from key ID
    """
    if len(key_seed) < 30:
        raise Exception("seed must be >= 30 bytes")
    key_seed = b64decode(key_seed)
    # key ID should be a UUID
    if isinstance(key_id, str):
        key_id = uuid.UUID(key_id)
    elif isinstance(key_id, bytes):
        key_id = uuid.UUID(str(key_id, "ASCII"))
    elif isinstance(key_id, uuid.UUID):
        pass
    else:
        raise TypeError("key_id should be a uuid")

    key_id = key_id.bytes_le

    sha = SHA256.new()
    sha.update(key_seed)
    sha.update(key_id)
    sha_a = [x for x in sha.digest()]

    sha = SHA256.new()
    sha.update(key_seed)
    sha.update(key_id)
    sha.update(key_seed)
    sha_b = [x for x in sha.digest()]

    sha = SHA256.new()
    sha.update(key_seed)
    sha.update(key_id)
    sha.update(key_seed)
    sha.update(key_id)
    sha_c = [x for x in sha.digest()]

    content_key = b""
    for i in range(16):
        content_key += (
            sha_a[i] ^ sha_a[i + 16] ^ sha_b[i] ^ sha_b[i + 16] ^ sha_c[i] ^
            sha_c[i + 16]).to_bytes(1, byteorder='big')

    return b16encode(content_key)


def checksum(key_id, key):
    """
    Generate playready key checksum

    From
    https://docs.microsoft.com/en-gb/playready/specifications/playready-header-specification#keychecksum

    For an ALGID value set to “AESCTR”, the 16-byte Key ID is encrypted with a
    16-byte AES content key using ECB mode. The first 8 bytes of the buffer is
    extracted and base64 encoded.
    """
    if isinstance(key_id, str):
        key_id = uuid.UUID(key_id)
    elif isinstance(key_id, bytes):
        key_id = uuid.UUID(bytes=key_id)
    
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    ciphertext = cipher.encrypt(key_id.bytes_le)

    return b64encode(ciphertext[:8])


def generate_wrmheader(key):
    """
    Generate Playready header 4.2 or 4.3 depending on the encryption algorithm
    specified
    """
    if isinstance(key["key_id"], str):
        key["key_id"] = uuid.UUID(key["key_id"])
    elif isinstance(key["key_id"], bytes):
        key["key_id"] = uuid.UUID(str(key["key_id"], "ASCII"))

    wrmheader = etree.Element("WRMHEADER", xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader", version="4.0.0.0")
    data_element = etree.SubElement(wrmheader, "DATA")
    protect_info_element = etree.SubElement(data_element, "PROTECTINFO")
    keylen_element = etree.SubElement(protect_info_element, "KEYLEN")
    keylen_element.text = "16"
    algid_element = etree.SubElement(protect_info_element, "ALGID")
    algid_element.text = "AESCTR"
    kid_element = etree.SubElement(data_element, "KID")
    kid_element.text = b64encode(key["key_id"].bytes_le)
    checksum_element = etree.SubElement(data_element, "CHECKSUM")
    checksum_element.text = checksum(**key).decode()

    return etree.tostring(wrmheader, encoding="utf-16le",
                          xml_declaration=False)


def generate_playready_object(wrmheader):
    """
    Generate a playready object from a wrmheader
    """
    return ((len(wrmheader) + 10).to_bytes(4, "little") +   # overall length
            (1).to_bytes(2, "little") +                     # record count
            (1).to_bytes(2, "little") +                     # record type
            len(wrmheader).to_bytes(2, "little") +          # wrmheader length
            wrmheader)                                      # wrmheader


def generate_pssh(key):
    """
    Generate a PSSH box including Playready header

    Defaults to version 1 with key IDs listed
    """
    wrmheader = generate_wrmheader(key)
    pro = generate_playready_object(wrmheader)

    pssh = pssh_box.build({
        "version": 0,
        "key_ids": [key["key_id"].bytes],
        "data": pro
    })

    return b64encode(pssh).decode(), b64encode(pro).decode()
