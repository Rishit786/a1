import io
import gzip
import zipfile
import base64
from PIL import Image
import pyaadhaar
from pyaadhaar.utils import SHAGenerator, isSecureQr, AadhaarQrAuto, Qr_img_to_text
from pyaadhaar.decode import AadhaarSecureQr, AadhaarOldQr, AadhaarOfflineXML


def test_sha_generator():
    hash_val = SHAGenerator('test@example.com', '4')
    assert len(hash_val) == 64
    assert isinstance(hash_val, str)


def test_secure_qr_decoding():
    # Build a sample secure QR payload
    img = Image.new('RGB', (20, 20), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    jpeg_data = buf.getvalue()

    email = 'test@example.com'
    mobile = '9876543210'
    last_digit = '4'

    email_hash = bytes.fromhex(SHAGenerator(email, last_digit))
    mobile_hash = bytes.fromhex(SHAGenerator(mobile, last_digit))

    fields = [
        '3', '12342020107890441252', 'Rahul Sharma', '15-08-1990', 'M',
        'S/O: Ramesh Sharma', 'New Delhi', 'Near Metro Station', 'Flat 402',
        'Connaught Place', '110001', 'Connaught Place SO', 'Delhi', 'Barakhamba Road',
        'New Delhi', 'New Delhi'
    ]

    raw_bytes = b'\xff'.join(f.encode('ISO-8859-1') for f in fields) + b'\xff'
    raw_bytes += jpeg_data
    raw_bytes += email_hash + mobile_hash + (b'\xab' * 256)

    compressed = gzip.compress(raw_bytes)
    big_int = int.from_bytes(compressed, 'big')

    # Test with string representation of big integer
    obj = AadhaarSecureQr(str(big_int))
    data = obj.decodeddata()

    assert data.get('name') == 'Rahul Sharma'
    assert data.get('dob') == '15-08-1990'
    assert data.get('gender') == 'M'
    assert data.get('pincode') == '110001'
    assert data.get('aadhaar_last_digit') == '4'

    assert obj.isImage() is True
    extracted_img = obj.image()
    assert extracted_img is not None
    assert extracted_img.size == (20, 20)

    # Verification
    assert obj.verifyEmail(email) is True
    assert obj.verifyEmail('wrong@example.com') is False
    assert obj.verifyMobileNumber(mobile) is True
    assert obj.verifyMobileNumber(int(mobile)) is True
    assert obj.verifyMobileNumber('1234567890') is False


def test_aadhaar_old_qr():
    old_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<PrintLetterBarcodeData uid="123456789012" name="Sunita Devi" gender="F" yob="1985" co="W/O: Raj Kumar" house="45" loc="Village" vtc="Rampur" po="Rampur" dist="Varanasi" subdist="Varanasi" state="Uttar Pradesh" pc="221001" dob="01/01/1985"/>'''
    obj = AadhaarQrAuto(old_xml)
    assert isinstance(obj, AadhaarOldQr)
    data = obj.decodeddata()
    assert data['name'] == 'Sunita Devi'
    assert data['uid'] == '123456789012'
    assert data['pc'] == '221001'


def test_aadhaar_offline_xml():
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<OfflinePaperlessKyc referenceId="34562020107890441252">
  <UidData>
    <Poi dob="15-08-1990" e="{e_hash}" gender="M" m="{m_hash}" name="Rahul Sharma"/>
    <Poa careof="S/O: Ramesh Sharma" country="India" dist="New Delhi" house="Flat 402" landmark="Near Metro" loc="CP" pc="110001" po="Connaught Place SO" state="Delhi" street="Barakhamba Rd" subdist="New Delhi" vtc="New Delhi"/>
    <Pht></Pht>
  </UidData>
</OfflinePaperlessKyc>'''.format(
        e_hash=SHAGenerator('test@example.com1234', '6'),
        m_hash=SHAGenerator('98765432101234', '6')
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('aadhaar_data.xml', xml_content)
    buf.seek(0)

    obj = AadhaarOfflineXML(buf, '1234')
    data = obj.decodeddata()
    assert data['name'] == 'Rahul Sharma'
    assert data['email_mobile_status'] == '3'
    assert obj.isEmailRegistered() is True
    assert obj.isMobileNoRegistered() is True
    assert obj.verifyEmail('test@example.com') is True
    assert obj.verifyMobileNumber('9876543210') is True
    assert obj.verifyMobileNumber(9876543210) is True


def test_qr_img_to_text():
    import zxingcpp
    # Generate a QR code image
    barcode = zxingcpp.create_barcode("HelloAadhaar123", zxingcpp.BarcodeFormat.QRCode)
    qr_img = zxingcpp.write_barcode_to_image(barcode)
    # Convert to PIL Image
    pil_img = Image.fromarray(qr_img)
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    buf.seek(0)

    # Test Qr_img_to_text with BytesIO
    results = Qr_img_to_text(buf)
    assert len(results) > 0
    assert "HelloAadhaar123" in results


if __name__ == '__main__':
    test_sha_generator()
    print("test_sha_generator passed")
    test_secure_qr_decoding()
    print("test_secure_qr_decoding passed")
    test_aadhaar_old_qr()
    print("test_aadhaar_old_qr passed")
    test_aadhaar_offline_xml()
    print("test_aadhaar_offline_xml passed")
    test_qr_img_to_text()
    print("test_qr_img_to_text passed")
    print("ALL TESTS PASSED SUCCESSFULLY!")
