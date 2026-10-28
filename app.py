import io
import sys
import time
import gzip
import zlib
import zipfile
import base64
from typing import Dict, Any, Optional
from flask import Flask, render_template, request, jsonify, send_file
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np

if hasattr(sys, 'set_int_max_str_digits'):
    try:
        sys.set_int_max_str_digits(50000)
    except Exception:
        pass

import pyaadhaar
from pyaadhaar.utils import Qr_img_to_text, isSecureQr, AadhaarQrAuto, SHAGenerator
from pyaadhaar.decode import AadhaarSecureQr, AadhaarOldQr, AadhaarOfflineXML
from document_verifier import DocumentQRExtractor, DocumentDetailsMatcher, parse_document_qr

try:
    import zxingcpp
    HAS_ZXING = True
except Exception:
    HAS_ZXING = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max upload

qr_extractor = DocumentQRExtractor()
details_matcher = DocumentDetailsMatcher()


def pil_to_base64(img: Optional[Image.Image]) -> Optional[str]:
    """Convert PIL image to base64 data URL."""
    if img is None:
        return None
    try:
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90)
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")
    except Exception:
        try:
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")
        except Exception:
            return None


def create_sample_avatar() -> bytes:
    """Generate a clean synthetic portrait thumbnail for testing."""
    img = Image.new('RGB', (60, 75), color=(235, 240, 248))
    draw = ImageDraw.Draw(img)
    draw.ellipse([8, 45, 52, 100], fill=(66, 133, 244))
    draw.ellipse([18, 15, 42, 45], fill=(245, 195, 150))
    draw.chord([16, 12, 44, 30], 180, 360, fill=(40, 40, 40))
    draw.ellipse([24, 25, 27, 28], fill=(30, 30, 30))
    draw.ellipse([33, 25, 36, 28], fill=(30, 30, 30))
    draw.rectangle([0, 0, 59, 74], outline=(180, 200, 220), width=1)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=65)
    return buf.getvalue()


def build_synthetic_secure_payload():
    """Build a synthetic Secure QR payload with valid hashes and photo."""
    photo_bytes = create_sample_avatar()
    email = "arjun.verma@example.com"
    mobile = "9876543210"
    ref_id = "56782024102890441258"
    last_digit = ref_id[3]  # '8'

    email_hash = bytes.fromhex(SHAGenerator(email, last_digit))
    mobile_hash = bytes.fromhex(SHAGenerator(mobile, last_digit))

    fields = [
        "3",  # Email + Mobile present
        ref_id,
        "Arjun Verma",
        "12-04-1992",
        "M",
        "S/O: Ramesh Verma",
        "South Delhi",
        "Near Lotus Temple",
        "Flat 302",
        "Kalkaji",
        "110019",
        "Kalkaji PO",
        "Delhi",
        "Nehru Place",
        "Kalkaji",
        "New Delhi"
    ]

    decompressed = b'\xff'.join(f.encode('ISO-8859-1') for f in fields) + b'\xff'
    decompressed += photo_bytes
    decompressed += email_hash + mobile_hash + (b'\x55' * 256)

    compressed = gzip.compress(decompressed)
    big_int = int.from_bytes(compressed, 'big')
    return str(big_int), email, mobile, ref_id


def extract_debug_details(obj, raw_input_str: Optional[str] = None) -> Dict[str, Any]:
    """Extract comprehensive debug and inspection details from a decoded object."""
    info: Dict[str, Any] = {
        'format_type': type(obj).__name__,
        'fields': {},
        'has_image': False,
        'photo_base64': None,
        'email_hash': None,
        'mobile_hash': None,
        'is_email_registered': False,
        'is_mobile_registered': False,
        'signature_hex': None,
        'signature_len': 0,
        'raw_len': len(raw_input_str) if raw_input_str else 0,
        'delimiters': [],
        'delimiters_count': 0,
        'decompressed_len': 0,
        'hex_preview': '',
        'debug_log': []
    }

    t0 = time.time()
    info['debug_log'].append(f"Started inspection of {type(obj).__name__}")

    try:
        data = obj.decodeddata()
        info['fields'] = data
        info['debug_log'].append(f"Decoded {len(data)} fields successfully")
    except Exception as e:
        info['debug_log'].append(f"Error fetching decodeddata: {str(e)}")

    if isinstance(obj, AadhaarSecureQr):
        info['format_type'] = "Aadhaar Secure QR (Encrypted / Compressed)"
        info['is_email_registered'] = obj.isEmailRegistered()
        info['is_mobile_registered'] = obj.isMobileNoRegistered()
        info['email_hash'] = obj.sha256hashOfEMail()
        info['mobile_hash'] = obj.sha256hashOfMobileNumber()
        info['delimiters'] = getattr(obj, 'delimeter', [])
        info['delimiters_count'] = len(info['delimiters'])

        decomp = getattr(obj, 'decompressed_array', b'')
        info['decompressed_len'] = len(decomp)
        if decomp:
            prefix_hex = decomp[:96].hex()
            suffix_hex = decomp[-64:].hex() if len(decomp) > 96 else ""
            info['hex_preview'] = f"{prefix_hex} ... [{len(decomp)} bytes total] ... {suffix_hex}"

        sig = obj.signature()
        info['signature_len'] = len(sig)
        info['signature_hex'] = sig[:32].hex() + ("..." if len(sig) > 32 else "")

        has_img = obj.isImage()
        info['has_image'] = bool(has_img)
        info['debug_log'].append(f"isImage check: {has_img}")

        if has_img:
            img = obj.image()
            if img:
                info['photo_base64'] = pil_to_base64(img)
                info['debug_log'].append(f"Photo extracted: {img.size[0]}x{img.size[1]} ({img.format or 'JPEG'})")

    elif isinstance(obj, AadhaarOldQr):
        info['format_type'] = "Aadhaar Old QR (Unencrypted XML v1.0)"
        info['has_image'] = False
        info['debug_log'].append("Old XML QR code parsed (no embedded photo or signature)")

    elif isinstance(obj, AadhaarOfflineXML):
        info['format_type'] = "Aadhaar Offline e-KYC XML (Password Protected)"
        info['is_email_registered'] = obj.isEmailRegistered()
        info['is_mobile_registered'] = obj.isMobileNoRegistered()
        info['email_hash'] = obj.sha256hashOfEMail()
        info['mobile_hash'] = obj.sha256hashOfMobileNumber()
        sig = obj.signature()
        info['signature_hex'] = sig[:64] + ("..." if len(sig) > 64 else "")
        info['signature_len'] = len(sig)

        img = obj.image()
        if img:
            info['has_image'] = True
            info['photo_base64'] = pil_to_base64(img)
            info['debug_log'].append(f"Offline XML photo extracted: {img.size[0]}x{img.size[1]}")

    elapsed_ms = round((time.time() - t0) * 1000, 2)
    info['debug_log'].append(f"Inspection completed in {elapsed_ms} ms")
    return info


@app.route('/')
def index():
    return render_template('index.html')


# =====================================================================
# Aadhaar Document Verifier & Details Matcher API
# =====================================================================

@app.route('/api/verify-document', methods=['POST'])
def verify_document():
    """
    Specifically engineered for full Aadhaar card photos (front, back, or e-Aadhaar).
    Extracts the QR code from anywhere on the Aadhaar card, decodes it,
    and reconciles every detail against the filled form fields.
    """
    t_start = time.time()
    file = request.files.get('file')

    # Gather user-filled Aadhaar details from form
    filled_details = {
        'name': request.form.get('name', '').strip(),
        'dob': request.form.get('dob', '').strip(),
        'gender': request.form.get('gender', '').strip(),
        'id_number': request.form.get('id_number', '').strip(),
        'care_of': request.form.get('care_of', '').strip(),
        'pincode': request.form.get('pincode', '').strip(),
        'address': request.form.get('address', '').strip(),
    }

    if not file:
        return jsonify({'success': False, 'error': 'No Aadhaar card image uploaded'}), 400

    img_bytes = file.read()

    # 1. Specifically extract QR code from Aadhaar card
    raw_qr_data, cropped_qr_img, extract_logs = qr_extractor.extract_qr_from_document(img_bytes)

    if not raw_qr_data:
        return jsonify({
            'success': False,
            'error': 'Could not detect an Aadhaar QR code on the card. Ensure the card is well-lit and the QR code is not heavily blurred or covered.',
            'extract_logs': extract_logs
        }), 422

    # 2. Parse the extracted Aadhaar QR data
    parsed_qr = parse_document_qr(raw_qr_data)

    if parsed_qr.get('doc_type') not in ('AADHAAR_SECURE_QR', 'AADHAAR_OLD_XML_QR', 'AADHAAR_SECURE'):
        return jsonify({
            'success': False,
            'error': 'The detected QR code is not a valid UIDAI Aadhaar QR code. Please upload a genuine Aadhaar card.',
            'extract_logs': extract_logs
        }), 422

    # 3. Reconcile details with filled form
    match_report = details_matcher.match(parsed_qr, filled_details)
    match_report['extract_logs'] = extract_logs
    match_report['qr_cropped_base64'] = pil_to_base64(cropped_qr_img)
    match_report['processing_time_ms'] = round((time.time() - t_start) * 1000, 1)

    return jsonify({
        'success': True,
        'report': match_report
    })


@app.route('/api/sample-document')
@app.route('/api/sample-document/<doc_type>')
def get_sample_document(doc_type='aadhaar'):
    """Generate a realistic full Aadhaar card image with embedded QR for 1-click testing."""
    big_int_str, _, _, _ = build_synthetic_secure_payload()
    if not HAS_ZXING or zxingcpp is None:
        return jsonify({'error': 'zxing-cpp required'}), 500

    bc = zxingcpp.create_barcode(big_int_str, zxingcpp.BarcodeFormat.QRCode)
    qr_arr = zxingcpp.write_barcode_to_image(bc)
    qr_pil = Image.fromarray(qr_arr).resize((300, 300), Image.NEAREST)

    # Full card image (1200 x 780)
    card = Image.new('RGB', (1200, 780), color=(255, 255, 255))
    draw = ImageDraw.Draw(card)

    # Tricolor header
    draw.rectangle([0, 0, 1200, 24], fill=(255, 153, 51))
    draw.rectangle([0, 24, 1200, 36], fill=(19, 136, 8))

    # Aadhaar Emblem & Header
    draw.text((60, 60), "GOVERNMENT OF INDIA / भारत सरकार", fill=(0, 0, 0))
    draw.text((60, 120), "Name / नाम: Arjun Verma", fill=(20, 20, 20))
    draw.text((60, 160), "DOB / जन्म तिथि: 12/04/1992", fill=(20, 20, 20))
    draw.text((60, 200), "Gender / लिंग: Male / पुरुष", fill=(20, 20, 20))
    draw.text((60, 250), "Address / पता: Flat 302, Nehru Place, Kalkaji, New Delhi 110019", fill=(50, 50, 50))
    draw.text((60, 350), "XXXX XXXX 5678", fill=(0, 0, 128))

    # Paste QR in bottom right quadrant
    card.paste(qr_pil, (860, 440))

    # Embed card inside a larger photo (desk surface)
    desk = Image.new('RGB', (1600, 1100), color=(220, 215, 205))
    desk.paste(card, (200, 160))

    buf = io.BytesIO()
    desk.save(buf, format="JPEG", quality=90)
    buf.seek(0)
    return send_file(buf, mimetype='image/jpeg', as_attachment=False)


# =====================================================================
# Existing Single QR Decode Endpoints
# =====================================================================

@app.route('/api/decode-image', methods=['POST'])
def decode_image():
    t_start = time.time()
    logs = [f"[{time.strftime('%H:%M:%S')}] Received image decode request"]

    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'error': 'No image file uploaded'}), 400

    img_bytes = file.read()
    logs.append(f"Uploaded file size: {len(img_bytes):,} bytes ({file.filename})")

    # Use robust document QR extractor
    raw_data, cropped_img, extract_logs = qr_extractor.extract_qr_from_document(img_bytes)
    logs.extend(extract_logs)

    if not raw_data:
        return jsonify({
            'success': False,
            'error': 'No QR code could be detected in this image. Ensure the card is well-lit and in focus.',
            'debug_log': logs
        }), 422

    logs.append(f"Raw QR payload length: {len(raw_data)} characters")
    is_secure = isSecureQr(raw_data)
    logs.append(f"Aadhaar QR type: {'Secure QR' if is_secure else 'Old QR / XML'}")

    try:
        obj = AadhaarQrAuto(raw_data)
        details = extract_debug_details(obj, raw_data)
        details['debug_log'] = logs + details['debug_log']
        details['debug_log'].append(f"Total processing time: {round((time.time() - t_start)*1000, 1)}ms")
        return jsonify({'success': True, 'data': details})
    except Exception as e:
        logs.append(f"Decoding error: {str(e)}")
        return jsonify({'success': False, 'error': f"Error decoding QR data: {str(e)}", 'debug_log': logs}), 500


@app.route('/api/decode-text', methods=['POST'])
def decode_text():
    t_start = time.time()
    logs = [f"[{time.strftime('%H:%M:%S')}] Received text decode request"]

    payload = request.get_json(silent=True) or {}
    text_data = (payload.get('text') or request.form.get('text') or '').strip()

    if not text_data:
        return jsonify({'success': False, 'error': 'No text or QR data provided'}), 400

    logs.append(f"Input text length: {len(text_data)} characters")
    is_sec = isSecureQr(text_data)
    logs.append(f"Type check: {'Secure QR (numeric)' if is_sec else 'Old QR / XML'}")

    try:
        obj = AadhaarQrAuto(text_data)
        details = extract_debug_details(obj, text_data)
        details['debug_log'] = logs + details['debug_log']
        details['debug_log'].append(f"Total processing time: {round((time.time() - t_start)*1000, 1)}ms")
        return jsonify({'success': True, 'data': details})
    except Exception as e:
        logs.append(f"Decoding failed: {str(e)}")
        return jsonify({'success': False, 'error': f"Error decoding text payload: {str(e)}", 'debug_log': logs}), 500


@app.route('/api/decode-xml', methods=['POST'])
def decode_xml():
    t_start = time.time()
    logs = [f"[{time.strftime('%H:%M:%S')}] Received Offline e-KYC XML decode request"]

    file = request.files.get('file')
    passcode = (request.form.get('passcode') or '').strip()

    if not file:
        return jsonify({'success': False, 'error': 'No e-KYC ZIP file uploaded'}), 400
    if not passcode:
        return jsonify({'success': False, 'error': '4-digit share code / passcode is required'}), 400

    zip_bytes = file.read()
    logs.append(f"ZIP file size: {len(zip_bytes):,} bytes, Passcode provided: {'*' * len(passcode)}")

    try:
        obj = AadhaarOfflineXML(zip_bytes, passcode)
        details = extract_debug_details(obj)
        details['debug_log'] = logs + details['debug_log']
        details['debug_log'].append(f"Total processing time: {round((time.time() - t_start)*1000, 1)}ms")
        return jsonify({'success': True, 'data': details})
    except zipfile.BadZipFile:
        return jsonify({'success': False, 'error': 'The uploaded file is not a valid ZIP archive', 'debug_log': logs}), 400
    except RuntimeError as e:
        if 'password' in str(e).lower():
            return jsonify({'success': False, 'error': 'Incorrect passcode / share code for this ZIP file', 'debug_log': logs}), 400
        return jsonify({'success': False, 'error': str(e), 'debug_log': logs}), 500
    except Exception as e:
        logs.append(f"XML parse error: {str(e)}")
        return jsonify({'success': False, 'error': f"Failed to process Offline XML: {str(e)}", 'debug_log': logs}), 500


@app.route('/api/verify', methods=['POST'])
def verify():
    data = request.get_json(silent=True) or {}
    raw_data = data.get('raw_data', '')
    qr_type = data.get('type', 'auto')
    email = (data.get('email') or '').strip()
    mobile = (data.get('mobile') or '').strip()

    if not email and not mobile:
        return jsonify({'success': False, 'error': 'Provide an email or mobile number to verify'}), 400

    results: Dict[str, Any] = {}

    try:
        if qr_type == 'offline_xml':
            return jsonify({'success': False, 'error': 'Please use verify within Offline XML tab'}), 400

        obj = AadhaarQrAuto(raw_data)

        if email:
            try:
                is_valid = obj.verifyEmail(email)
                calculated_hash = SHAGenerator(email, obj.decodeddata().get('aadhaar_last_digit', ''))
                stored_hash = obj.sha256hashOfEMail()
                results['email'] = {
                    'verified': bool(is_valid),
                    'input': email,
                    'calculated_hash': calculated_hash,
                    'stored_hash': stored_hash,
                    'match': bool(is_valid)
                }
            except Exception as e:
                results['email'] = {'verified': False, 'error': str(e)}

        if mobile:
            try:
                is_valid = obj.verifyMobileNumber(mobile)
                calculated_hash = SHAGenerator(mobile, obj.decodeddata().get('aadhaar_last_digit', ''))
                stored_hash = obj.sha256hashOfMobileNumber()
                results['mobile'] = {
                    'verified': bool(is_valid),
                    'input': mobile,
                    'calculated_hash': calculated_hash,
                    'stored_hash': stored_hash,
                    'match': bool(is_valid)
                }
            except Exception as e:
                results['mobile'] = {'verified': False, 'error': str(e)}

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Verification error: {str(e)}"}), 500


@app.route('/api/sample/<sample_type>')
def get_sample(sample_type):
    if sample_type == 'secure-qr':
        big_int_str, email, mobile, ref_id = build_synthetic_secure_payload()
        return jsonify({
            'success': True,
            'type': 'secure-qr',
            'raw_text': big_int_str,
            'sample_email': email,
            'sample_mobile': mobile,
            'description': 'UIDAI Synthetic Secure Aadhaar QR Code (V2 format with Photo, Email & Mobile Hashes)'
        })

    elif sample_type == 'old-qr':
        old_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<PrintLetterBarcodeData uid="987654321098" name="Priya Sharma" gender="F" yob="1995" '
            'co="D/O: Mohan Sharma" house="H-44" loc="Civil Lines" vtc="Jaipur" po="Civil Lines SO" '
            'dist="Jaipur" subdist="Jaipur" state="Rajasthan" pc="302006" dob="14/11/1995"/>'
        )
        return jsonify({
            'success': True,
            'type': 'old-qr',
            'raw_text': old_xml,
            'description': 'Old Aadhaar QR Code (XML v1.0 standard)'
        })

    elif sample_type == 'qr-image':
        big_int_str, _, _, _ = build_synthetic_secure_payload()
        if HAS_ZXING and zxingcpp is not None:
            try:
                bc = zxingcpp.create_barcode(big_int_str, zxingcpp.BarcodeFormat.QRCode)
                arr = zxingcpp.write_barcode_to_image(bc)
                pil_img = Image.fromarray(arr).resize((400, 400), Image.NEAREST)
                buf = io.BytesIO()
                pil_img.save(buf, format="PNG")
                buf.seek(0)
                return send_file(buf, mimetype='image/png', as_attachment=False, download_name='sample_aadhaar_qr.png')
            except Exception:
                pass
        return jsonify({'error': 'Image generation failed'}), 500

    return jsonify({'error': 'Unknown sample type'}), 404


if __name__ == '__main__':
    import socket
    port = 5050
    for p in [5050, 8000, 8080, 5001]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', p)) != 0:
                port = p
                break

    print("=" * 65)
    print("  PyAadhaar Interactive Web Application & Live Debugger")
    print(f"  Running on: http://127.0.0.1:{port} (http://localhost:{port})")
    print("=" * 65)
    app.run(host='127.0.0.1', port=port, debug=False)
