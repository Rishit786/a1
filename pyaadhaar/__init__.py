import sys

# Increase integer string conversion limit for Python 3.11+
# Aadhaar Secure QR codes contain high-density numeric payloads (often 5000+ digits)
if hasattr(sys, 'set_int_max_str_digits'):
    try:
        sys.set_int_max_str_digits(50000)
    except Exception:
        pass

from .decode import (
    AadhaarSecureQr,
    AadhaarOldQr,
    AadhaarOfflineXML,
    AdhaarSecureQr,
    AdhaarOldQr,
    AdhaarOfflineXML,
)
from .utils import (
    AadhaarQrAuto,
    isSecureQr,
    Qr_img_to_text,
    SHAGenerator,
)

__all__ = [
    'AadhaarSecureQr',
    'AadhaarOldQr',
    'AadhaarOfflineXML',
    'AdhaarSecureQr',
    'AdhaarOldQr',
    'AdhaarOfflineXML',
    'AadhaarQrAuto',
    'isSecureQr',
    'Qr_img_to_text',
    'SHAGenerator',
]
