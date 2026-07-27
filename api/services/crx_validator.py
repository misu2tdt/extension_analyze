# api/services/crx_validator.py
import struct
from io import BytesIO


CRX_MAGIC = b'Cr24'


class InvalidCRXError(Exception):
    pass


def validate_crx(content: bytes) -> dict:
    """
    Quick validation: check magic bytes + extract version.
    Return basic info. Doesn't parse manifest yet.
    """
    if len(content) < 16:
        raise InvalidCRXError("File too small to be CRX")
    
    # Check magic bytes
    magic = content[:4]
    if magic != CRX_MAGIC:
        raise InvalidCRXError(f"Invalid CRX magic bytes: {magic}")
    
    # CRX version (bytes 4-7, little endian uint32)
    version = struct.unpack('<I', content[4:8])[0]
    if version not in (2, 3):
        raise InvalidCRXError(f"Unsupported CRX version: {version}")
    
    return {
        "version": version,
        "size_bytes": len(content),
        "valid": True
    }