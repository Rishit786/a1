import sys
import zlib
from io import BytesIO
from PIL import Image, ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = True

if hasattr(sys, 'set_int_max_str_digits'):
    try:
        sys.set_int_max_str_digits(50000)
    except Exception:
        pass
import xml.etree.ElementTree as ET
import base64
import zipfile
from typing import Union
from . import utils


class AadhaarSecureQr:
    # This is the class for Aadhaar Secure Qr code.. In this version of code the data is in compressed format
    # The special thing of this type of QR is that we can extract the photo of user from the data
    # This class supports versions of Aadhaar QR codes (V2, V3, V5, etc.)
    # For more information check here: https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, base10encodedstring: Union[str, int, bytes]) -> None:
        self.base10encodedstring = base10encodedstring
        self.details = [
            "email_mobile_status", "referenceid", "name", "dob", "gender", "careof",
            "district", "landmark", "house", "location", "pincode", "postoffice",
            "state", "street", "subdistrict", "vtc"
        ]
        self.delimeter = [-1]
        self.data = {}
        self._convert_base10encoded_to_decompressed_array()
        self._check_for_version()  # Check if Vx format exists
        self._create_delimeter()
        self._extract_info_from_decompressed_array()

    # Converts base10encoded string or integer or bytes to a decompressed array
    def _convert_base10encoded_to_decompressed_array(self) -> None:
        if isinstance(self.base10encodedstring, str):
            clean_str = self.base10encodedstring.strip()
            try:
                self.base10encodedstring = int(clean_str)
            except ValueError:
                # If not purely numeric string, try direct bytes
                bytes_array = clean_str.encode('latin1')
                self._decompress_bytes(bytes_array)
                return

        if isinstance(self.base10encodedstring, int):
            byte_len = max(5000, (self.base10encodedstring.bit_length() + 7) // 8)
            bytes_array = self.base10encodedstring.to_bytes(byte_len, 'big').lstrip(b'\x00')
        elif isinstance(self.base10encodedstring, (bytes, bytearray)):
            bytes_array = bytes(self.base10encodedstring).lstrip(b'\x00')
        else:
            raise TypeError("base10encodedstring must be str, int, or bytes")

        self._decompress_bytes(bytes_array)

    def _decompress_bytes(self, bytes_array: bytes) -> None:
        try:
            # Gzip decompression with 16 + MAX_WBITS
            self.decompressed_array = zlib.decompress(bytes_array, 16 + zlib.MAX_WBITS)
        except Exception:
            try:
                # Auto-detect gzip or standard zlib wrapper (32 + MAX_WBITS)
                self.decompressed_array = zlib.decompress(bytes_array, 32 + zlib.MAX_WBITS)
            except Exception:
                # Direct raw or standard zlib
                self.decompressed_array = zlib.decompress(bytes_array)

    def _check_for_version(self) -> None:
        """Check for Vx version markers (non-standard extension)"""
        version_marker = self.decompressed_array[:2].decode("ISO-8859-1", errors='ignore')
        if version_marker.startswith("V") and len(version_marker) > 1 and version_marker[1].isdigit():
            # If version marker exists, add version and mobile fields
            if "version" not in self.details:
                self.details.insert(0, "version")
            if "last_4_digits_mobile_no" not in self.details:
                self.details.append("last_4_digits_mobile_no")

    # Creates the delimeter which is used to extract the information from the decompressed array
    def _create_delimeter(self) -> None:
        self.delimeter = [-1]
        for i in range(len(self.decompressed_array)):
            if self.decompressed_array[i] == 255:
                self.delimeter.append(i)

    # Extracts the information from the decompressed array
    def _extract_info_from_decompressed_array(self) -> None:
        for i in range(len(self.details)):
            if i + 1 < len(self.delimeter):
                self.data[self.details[i]] = self.decompressed_array[
                    self.delimeter[i] + 1 : self.delimeter[i+1]
                ].decode("ISO-8859-1")
            else:
                self.data[self.details[i]] = ""

        # Extract last 4 digits of Aadhaar (first 4 chars of referenceId)
        ref_id = self.data.get('referenceid', '')
        self.data['aadhaar_last_4_digit'] = ref_id[:4] if len(ref_id) >= 4 else ref_id

        # Extract last digit of Aadhaar (4th char of referenceId, index 3)
        self.data['aadhaar_last_digit'] = ref_id[3] if len(ref_id) > 3 else ''

        # Set email/mobile flags based on email_mobile_status
        status = self.data.get('email_mobile_status', '0')
        try:
            status_int = int(status)
        except (ValueError, TypeError):
            status_int = 0
        self.data['email'] = status_int in {1, 3}
        self.data['mobile'] = status_int in {2, 3}

    # Returns the extracted data in a dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Returns signature of the QR code (last 256 bytes)
    def signature(self) -> bytes:
        if len(self.decompressed_array) >= 256:
            return self.decompressed_array[len(self.decompressed_array) - 256 :]
        return b""

    # Returns the signed data of the QR code
    def signedData(self) -> bytes:
        if len(self.decompressed_array) >= 256:
            return self.decompressed_array[: len(self.decompressed_array) - 256]
        return self.decompressed_array

    # Check whether mobile no is registered or not
    def isMobileNoRegistered(self) -> bool:
        return self.data.get('mobile', False)

    # Check whether email id is registered or not
    def isEmailRegistered(self) -> bool:
        return self.data.get('email', False)

    # Return hash of the email id
    def sha256hashOfEMail(self) -> str:
        # V3/V5 format uses masked last 4 digits in text field instead of SHA hash
        if 'version' in self.data and self.data.get('version') in ('V3', 'V5'):
            return ""

        status = self.data.get('email_mobile_status', '0')
        try:
            status_int = int(status)
        except (ValueError, TypeError):
            status_int = 0

        total_len = len(self.decompressed_array)
        tmp = ""
        if status_int == 3 and total_len >= 256 + 32 + 32:
            # When both present: email is at [len-256-32-32 : len-256-32]
            tmp = self.decompressed_array[total_len - 256 - 64 : total_len - 256 - 32].hex()
        elif status_int == 1 and total_len >= 256 + 32:
            # When only email: email is at [len-256-32 : len-256]
            tmp = self.decompressed_array[total_len - 256 - 32 : total_len - 256].hex()
        return tmp

    # Return hash of the mobile number
    def sha256hashOfMobileNumber(self) -> str:
        # V3/V5 format uses masked last 4 digits in text field instead of SHA hash
        if 'version' in self.data and self.data.get('version') in ('V3', 'V5'):
            return ""

        status = self.data.get('email_mobile_status', '0')
        try:
            status_int = int(status)
        except (ValueError, TypeError):
            status_int = 0

        total_len = len(self.decompressed_array)
        if status_int in {3, 2} and total_len >= 256 + 32:
            # When both (3) or only mobile (2): mobile is at [len-256-32 : len-256]
            return self.decompressed_array[total_len - 256 - 32 : total_len - 256].hex()
        return ""

    # Check availability of image in the QR CODE
    def isImage(self, buffer: int = 10) -> bool:
        total_len = len(self.decompressed_array)
        has_ver = 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5')

        if has_ver:
            last_text_delimiter_idx = len(self.details) - 2 if 'last_4_digits_mobile_no' in self.details else len(self.details) - 1
        else:
            last_text_delimiter_idx = len(self.details)

        if last_text_delimiter_idx >= len(self.delimeter):
            last_text_delimiter_idx = len(self.delimeter) - 1

        if last_text_delimiter_idx < 0:
            return False

        start_pos = self.delimeter[last_text_delimiter_idx] + 1

        if has_ver and self.data.get('version') in ('V3', 'V5'):
            # V3/V5 only signature after photo
            return len(self.decompressed_array[start_pos:]) >= 256 + buffer

        status = self.data.get('email_mobile_status', '0')
        try:
            status_int = int(status)
        except (ValueError, TypeError):
            status_int = 0

        if status_int == 3:
            return len(self.decompressed_array[start_pos:]) >= 256 + 32 + 32 + buffer
        elif status_int in {2, 1}:
            return len(self.decompressed_array[start_pos:]) >= 256 + 32 + buffer
        else:
            return len(self.decompressed_array[start_pos:]) >= 256 + buffer

    # Return image stream
    def image(self) -> Union[Image.Image, None]:
        total_len = len(self.decompressed_array)
        has_ver = 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5')

        # Photo starts after the delimiter following the last text field
        idx = len(self.details)
        if idx < len(self.delimeter):
            photo_start = self.delimeter[idx] + 1
        elif len(self.delimeter) > 1:
            photo_start = self.delimeter[-1] + 1
        else:
            photo_start = 0

        if has_ver and self.data.get('version') in ('V3', 'V5'):
            photo_end = total_len - 256
        else:
            status = self.data.get('email_mobile_status', '0')
            try:
                status_int = int(status)
            except (ValueError, TypeError):
                status_int = 0

            if status_int == 3:
                photo_end = total_len - 256 - 32 - 32
            elif status_int in {2, 1}:
                photo_end = total_len - 256 - 32
            else:
                photo_end = total_len - 256

        if photo_start < photo_end and photo_end <= total_len:
            try:
                return Image.open(BytesIO(self.decompressed_array[photo_start:photo_end]))
            except Exception:
                return None
        return None

    # Save the image of the user
    def saveimage(self, filepath: str) -> None:
        image = self.image()
        if image is not None:
            image.load()
            image.save(filepath)
        else:
            raise ValueError("No valid image found in QR code data")

    # Verify the email id
    def verifyEmail(self, emailid: str) -> bool:
        if not isinstance(emailid, str):
            raise TypeError("Email id should be string")
        sha_hash = self.sha256hashOfEMail()
        if not sha_hash:
            return False
        generated_sha_mail = utils.SHAGenerator(emailid, self.data.get('aadhaar_last_digit', ''))
        return generated_sha_mail.lower() == sha_hash.lower()

    # Verify the mobile no
    def verifyMobileNumber(self, mobileno: Union[str, int]) -> bool:
        if isinstance(mobileno, int):
            mobileno = str(mobileno)
        elif not isinstance(mobileno, str):
            raise TypeError("Mobile number should be string or integer")

        mobileno = mobileno.strip()

        # V5 format
        if 'version' in self.data and self.data.get('version') == 'V5':
            masked = self.data.get('last_4_digits_mobile_no', '')
            if not masked or len(masked) < 4 or len(mobileno) < 4:
                return False
            return mobileno[-4:] == masked[-4:]

        # V3 format with last_4_digits_mobile_no field
        if 'last_4_digits_mobile_no' in self.data and self.data.get('last_4_digits_mobile_no'):
            return mobileno[-4:] == self.data['last_4_digits_mobile_no']

        # V2 format or standard: verify by SHA256 hash
        sha_hash = self.sha256hashOfMobileNumber()
        if not sha_hash:
            return False
        generated_sha_mobile = utils.SHAGenerator(mobileno, self.data.get('aadhaar_last_digit', ''))
        return generated_sha_mobile.lower() == sha_hash.lower()


class AadhaarOldQr:
    # This is the class for Aadhaar Normal Qr code.. In this version of code the data is in XML v1.0 format
    # For more information check here : https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, qrdata: Union[str, bytes]) -> None:
        self.qrdata = qrdata
        if isinstance(qrdata, bytes):
            qrdata = qrdata.decode('utf-8', errors='ignore')
        self.xmlparser = ET.XMLParser(encoding="utf-8")
        self.parsedxml = ET.fromstring(qrdata.strip(), parser=self.xmlparser)
        self.data = self.parsedxml.attrib

    def decodeddata(self) -> dict:
        return self.data

    def isImage(self) -> bool:
        return False

    def image(self) -> None:
        return None

    def saveimage(self, filepath: str) -> None:
        raise NotImplementedError("Old Aadhaar QR code does not contain user photo")


class AadhaarOfflineXML:
    # This is the class for Aadhaar Offline XML
    # Can extract user details and the high-resolution photo from the data
    # For more information check here : https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, file: Union[str, BytesIO, bytes], passcode: str) -> None:
        self.passcode = str(passcode)
        self.data = {}

        if isinstance(file, (bytes, bytearray)):
            file = BytesIO(file)

        zf = zipfile.ZipFile(file, 'r')
        zf.setpassword(self.passcode.encode('utf-8'))

        # Locate XML file in ZIP archive
        xml_filename = None
        for name in zf.namelist():
            if name.lower().endswith('.xml'):
                xml_filename = name
                break
        if xml_filename is None:
            xml_filename = zf.namelist()[0]

        filedata = zf.open(xml_filename).read()
        self.root = ET.fromstring(filedata, parser=ET.XMLParser(encoding="utf-8"))

        # Find POI (Proof of Identity), POA (Proof of Address), and PHT (Photo)
        poi = self.root.find('.//Poi')
        if poi is None and len(self.root) > 0 and len(self.root[0]) > 0:
            poi = self.root[0][0]
        poi_attrib = poi.attrib if poi is not None else {}

        poa = self.root.find('.//Poa')
        if poa is None and len(self.root) > 0 and len(self.root[0]) > 1:
            poa = self.root[0][1]
        poa_attrib = poa.attrib if poa is not None else {}

        self.hashofmobile = poi_attrib.get('m', '')
        self.hashofemail = poi_attrib.get('e', '')

        # Correct UIDAI status codes:
        # 0: Neither mobile nor email
        # 1: Email only
        # 2: Mobile only
        # 3: Both email and mobile
        if self.hashofmobile != "" and self.hashofemail != "":
            self.data['email_mobile_status'] = "3"
        elif self.hashofmobile != "" and self.hashofemail == "":
            self.data['email_mobile_status'] = "2"
        elif self.hashofmobile == "" and self.hashofemail != "":
            self.data['email_mobile_status'] = "1"
        else:
            self.data['email_mobile_status'] = "0"

        self.data['referenceid'] = self.root.attrib.get('referenceId', '')
        self.data['name'] = poi_attrib.get('name', '')
        self.data['dob'] = poi_attrib.get('dob', '')
        self.data['gender'] = poi_attrib.get('gender', '')
        self.data['careof'] = poa_attrib.get('careof', '')
        self.data['district'] = poa_attrib.get('dist', '')
        self.data['landmark'] = poa_attrib.get('landmark', '')
        self.data['house'] = poa_attrib.get('house', '')
        self.data['location'] = poa_attrib.get('loc', '')
        self.data['pincode'] = poa_attrib.get('pc', '')
        self.data['postoffice'] = poa_attrib.get('po', '')
        self.data['state'] = poa_attrib.get('state', '')
        self.data['street'] = poa_attrib.get('street', '')
        self.data['subdistrict'] = poa_attrib.get('subdist', '')
        self.data['vtc'] = poa_attrib.get('vtc', '')
        self.data['aadhaar_last_4_digit'] = self.data['referenceid'][0:4] if len(self.data['referenceid']) >= 4 else self.data['referenceid']
        self.data['aadhaar_last_digit'] = self.data['referenceid'][3] if len(self.data['referenceid']) > 3 else ''

        self.data['email'] = self.data['email_mobile_status'] in {"1", "3"}
        self.data['mobile'] = self.data['email_mobile_status'] in {"2", "3"}

    # Get decoded data in dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Fetch signature
    def signature(self) -> str:
        # Search for Signature node
        sig = self.root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
        if sig is not None and sig.text:
            return sig.text.strip()
        if len(self.root) > 1 and len(self.root[1]) > 1 and self.root[1][1].text:
            return self.root[1][1].text.strip()
        return ""

    # Check if mobile number is registered
    def isMobileNoRegistered(self) -> bool:
        return self.data.get('mobile', False)

    # Check if email id is registered
    def isEmailRegistered(self) -> bool:
        return self.data.get('email', False)

    # Get the hash of email id
    def sha256hashOfEMail(self) -> str:
        return self.hashofemail

    # Get the hash of mobile number
    def sha256hashOfMobileNumber(self) -> str:
        return self.hashofmobile

    # Get the image of user
    def image(self) -> Union[Image.Image, None]:
        pht = self.root.find('.//Pht')
        if pht is None and len(self.root) > 0 and len(self.root[0]) > 2:
            pht = self.root[0][2]
        if pht is not None and pht.text:
            try:
                img_data = base64.b64decode(pht.text.strip())
                return Image.open(BytesIO(img_data))
            except Exception:
                return None
        return None

    # Save the image of user
    def saveimage(self, filepath: str) -> None:
        image = self.image()
        if image is not None:
            image.load()
            image.save(filepath)
        else:
            raise ValueError("No valid image found in Offline XML")

    # Verify the email id
    def verifyEmail(self, emailid: str) -> bool:
        if not isinstance(emailid, str):
            raise TypeError("Email id should be string")
        if not self.hashofemail:
            return False
        generated_sha_mail = utils.SHAGenerator(
            str(emailid) + str(self.passcode), self.data.get('aadhaar_last_digit', ''))
        return generated_sha_mail.lower() == self.hashofemail.lower()

    # Verify the mobile number
    def verifyMobileNumber(self, mobileno: Union[str, int]) -> bool:
        if isinstance(mobileno, int):
            mobileno = str(mobileno)
        elif not isinstance(mobileno, str):
            raise TypeError("Mobile number should be string or integer")
        if not self.hashofmobile:
            return False
        generated_sha_mobile = utils.SHAGenerator(
            str(mobileno) + str(self.passcode), self.data.get('aadhaar_last_digit', ''))
        return generated_sha_mobile.lower() == self.hashofmobile.lower()


# Backward compatibility aliases
AdhaarSecureQr = AadhaarSecureQr
AdhaarOldQr = AadhaarOldQr
AdhaarOfflineXML = AadhaarOfflineXML
