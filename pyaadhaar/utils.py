import os
import sys
from io import BytesIO
from hashlib import sha256
from typing import List, Union

if hasattr(sys, 'set_int_max_str_digits'):
    try:
        sys.set_int_max_str_digits(50000)
    except Exception:
        pass
from PIL import Image
import cv2
import numpy as np

# Optional pyzbar import with fallback
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    _has_pyzbar = True
except Exception:
    pyzbar_decode = None
    _has_pyzbar = False

# Optional zxingcpp import with fallback
try:
    import zxingcpp
    _has_zxing = True
except Exception:
    zxingcpp = None
    _has_zxing = False


def SHAGenerator(string, n):
    # This function is to generate the hash for given emailid and mobile

    # To verify mobile/email, first obtain the fourth digit of reference id (last
    # digit of Aadhaar number). If it is 0 or 1 then converts provided Input
    # mobile/mail id into sha256 value of provide data. In case of 2 to 9 convert
    # the sha256 value for same number of times. This converted value should
    # match with the value received in 8. If value not matching means
    # mobile/email not verified.

    # For more read here : https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    tmp_sha = str(string)
    try:
        n_int = int(n)
    except (ValueError, TypeError):
        n_int = 1

    if n_int == 0 or n_int == 1:
        return sha256(tmp_sha.encode()).hexdigest()
    for _ in range(n_int):
        tmp_sha = sha256(tmp_sha.encode()).hexdigest()
    return tmp_sha


def isSecureQr(sample):
    # This function will return True if it is a newly released secure QR code
    # Will return False if it is old Aadhaar QR codes or XML
    if isinstance(sample, int):
        return True
    if isinstance(sample, (bytes, bytearray)):
        try:
            sample = sample.decode('utf-8')
        except Exception:
            return False
    try:
        int(str(sample).strip())
        return True
    except (ValueError, TypeError):
        return False


def AadhaarQrAuto(data):
    # This function will first check the type of qrcode and will
    # create the object of respective class and will return the object
    from . import decode
    if isSecureQr(data):
        return decode.AadhaarSecureQr(data)
    else:
        return decode.AadhaarOldQr(data)


def _load_image(file):
    """Load image from path, bytes, file stream, PIL Image, or numpy array."""
    if isinstance(file, np.ndarray):
        return file
    if isinstance(file, Image.Image):
        return cv2.cvtColor(np.array(file), cv2.COLOR_RGB2BGR)
    if hasattr(file, 'read'):
        data = file.read()
        if isinstance(file, BytesIO) or hasattr(file, 'seek'):
            try:
                file.seek(0)
            except Exception:
                pass
        arr = np.frombuffer(data, dtype=np.uint8)
        return cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if isinstance(file, (bytes, bytearray)):
        arr = np.frombuffer(file, dtype=np.uint8)
        return cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if isinstance(file, str):
        # Support Unicode paths on Windows
        try:
            return cv2.imdecode(np.fromfile(file, dtype=np.uint8), cv2.IMREAD_COLOR)
        except Exception:
            return cv2.imread(file)
    return None


def Qr_img_to_text(file) -> List[str]:
    # This function will extract all QR code data from image
    # And will return a list of data of all QR codes
    img = _load_image(file)
    if img is None:
        return []

    totaldata = []

    # 1. Try zxing-cpp if available (fastest and best for dense Aadhaar QR codes)
    if _has_zxing and zxingcpp is not None:
        try:
            results = zxingcpp.read_barcodes(img)
            for result in results:
                if result.text:
                    totaldata.append(result.text)
                elif result.bytes:
                    try:
                        totaldata.append(result.bytes.decode('utf-8'))
                    except Exception:
                        totaldata.append(result.bytes.decode('iso-8859-1', errors='ignore'))
        except Exception:
            pass

    # 2. Try pyzbar if available and no data found yet
    if not totaldata and _has_pyzbar and pyzbar_decode is not None:
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            code = pyzbar_decode(gray)
            for i in code:
                try:
                    decodeddata = i.data.decode('utf-8')
                except Exception:
                    decodeddata = i.data.decode('iso-8859-1', errors='ignore')
                totaldata.append(decodeddata)
        except Exception:
            pass

    # 3. Try OpenCV QRCodeDetector as fallback
    if not totaldata:
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            detector = cv2.QRCodeDetector()
            # Try multi-decode
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(gray)
            if ok:
                for text in decoded_info:
                    if text:
                        totaldata.append(text)
            if not totaldata:
                # Try single decode
                val, _, _ = detector.detectAndDecode(gray)
                if val:
                    totaldata.append(val)
        except Exception:
            pass

    # 4. Try with adaptive thresholding / contrast enhancement if still not detected
    if not totaldata:
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            # Enhance contrast using CLAHE
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)

            if _has_zxing and zxingcpp is not None:
                results = zxingcpp.read_barcodes(enhanced)
                for r in results:
                    if r.text:
                        totaldata.append(r.text)
                    elif r.bytes:
                        try:
                            totaldata.append(r.bytes.decode('utf-8'))
                        except Exception:
                            totaldata.append(r.bytes.decode('iso-8859-1', errors='ignore'))

            if not totaldata and _has_pyzbar and pyzbar_decode is not None:
                code = pyzbar_decode(enhanced)
                for i in code:
                    try:
                        decodeddata = i.data.decode('utf-8')
                    except Exception:
                        decodeddata = i.data.decode('iso-8859-1', errors='ignore')
                    totaldata.append(decodeddata)
        except Exception:
            pass

    return totaldata
