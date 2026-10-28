"""
document_verifier.py - Aadhaar QR Extractor & Details Reconciliation Engine
Specifically engineered for locating, cropping, and decoding QR codes from full
Aadhaar identity card images (Aadhaar front, Aadhaar back, e-Aadhaar slips, camera photos)
and matching extracted Aadhaar details against user-filled form details.
"""

import io
import re
import sys
import difflib
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List, Union
from PIL import Image
import cv2
import numpy as np

# Increase integer string limit for Python 3.11+
if hasattr(sys, 'set_int_max_str_digits'):
    try:
        sys.set_int_max_str_digits(50000)
    except Exception:
        pass

import pyaadhaar
from pyaadhaar.utils import isSecureQr, AadhaarQrAuto
from pyaadhaar.decode import AadhaarSecureQr, AadhaarOldQr

try:
    import zxingcpp
    HAS_ZXING = True
except Exception:
    HAS_ZXING = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except Exception:
    HAS_PYZBAR = False


# =====================================================================
# 1. Advanced Aadhaar Card QR Extractor
# =====================================================================

class AadhaarQRExtractor:
    """
    Specifically engineered to locate, enhance, crop, and decode QR codes from
    full Aadhaar card photographs (e.g. phone photos of an Aadhaar card resting on
    a desk, with tilt, rotation, uneven lighting, or small QR code proportion).
    """

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def _to_cv2(self, img_input: Union[str, bytes, Image.Image, np.ndarray]) -> Optional[np.ndarray]:
        """Convert input to OpenCV BGR numpy array."""
        if isinstance(img_input, np.ndarray):
            return img_input
        if isinstance(img_input, Image.Image):
            return cv2.cvtColor(np.array(img_input), cv2.COLOR_RGB2BGR)
        if hasattr(img_input, 'read'):
            img_input = img_input.read()
        if isinstance(img_input, (bytes, bytearray)):
            arr = np.frombuffer(img_input, dtype=np.uint8)
            return cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if isinstance(img_input, str):
            try:
                return cv2.imdecode(np.fromfile(img_input, dtype=np.uint8), cv2.IMREAD_COLOR)
            except Exception:
                return cv2.imread(img_input)
        return None

    def _scan_mat(self, mat: np.ndarray) -> List[str]:
        """Try decoding a single image matrix using all available QR engines."""
        results = []
        if mat is None or mat.size == 0:
            return results

        # 1. zxingcpp (fastest and handles dense Aadhaar QR codes best)
        if HAS_ZXING and zxingcpp is not None:
            try:
                barcodes = zxingcpp.read_barcodes(mat)
                for b in barcodes:
                    if b.text:
                        results.append(b.text)
                    elif b.bytes:
                        try:
                            results.append(b.bytes.decode('utf-8'))
                        except Exception:
                            results.append(b.bytes.decode('iso-8859-1', errors='ignore'))
            except Exception:
                pass

        # 2. OpenCV QRCodeDetector
        if not results:
            try:
                gray = cv2.cvtColor(mat, cv2.COLOR_BGR2GRAY) if len(mat.shape) == 3 else mat
                ok, decoded_info, _, _ = self.detector.detectAndDecodeMulti(gray)
                if ok:
                    for text in decoded_info:
                        if text:
                            results.append(text)
                if not results:
                    val, _, _ = self.detector.detectAndDecode(gray)
                    if val:
                        results.append(val)
            except Exception:
                pass

        # 3. pyzbar (if available)
        if not results and HAS_PYZBAR and pyzbar_decode is not None:
            try:
                gray = cv2.cvtColor(mat, cv2.COLOR_BGR2GRAY) if len(mat.shape) == 3 else mat
                codes = pyzbar_decode(gray)
                for c in codes:
                    try:
                        results.append(c.data.decode('utf-8'))
                    except Exception:
                        results.append(c.data.decode('iso-8859-1', errors='ignore'))
            except Exception:
                pass

        return results

    def extract_qr_from_document(
        self,
        img_input: Union[str, bytes, Image.Image, np.ndarray]
    ) -> Tuple[Optional[str], Optional[Image.Image], List[str]]:
        """
        Multi-stage robust QR code extraction pipeline specifically tuned for Aadhaar cards.
        Returns:
            (decoded_qr_text, cropped_qr_image, logs)
        """
        logs = []
        img_bgr = self._to_cv2(img_input)
        if img_bgr is None:
            logs.append("Failed to load image input.")
            return None, None, logs

        orig_h, orig_w = img_bgr.shape[:2]
        logs.append(f"Loaded Aadhaar card image: {orig_w}x{orig_h} px")

        # -------------------------------------------------------------
        # Stage 1: Direct Scan on original image
        # -------------------------------------------------------------
        res = self._scan_mat(img_bgr)
        if res:
            logs.append("Stage 1 Success: Aadhaar QR code detected on direct original scan.")
            return res[0], None, logs

        # -------------------------------------------------------------
        # Stage 2: Multiscale Resizing
        # Downscale 3000px+ phone photos or upscale small cards
        # -------------------------------------------------------------
        scales = []
        max_dim = max(orig_h, orig_w)
        if max_dim > 2000:
            scales = [1800 / max_dim, 1400 / max_dim, 1000 / max_dim]
        elif max_dim < 900:
            scales = [1200 / max_dim, 1600 / max_dim]

        for s in scales:
            new_w, new_h = int(orig_w * s), int(orig_h * s)
            resized = cv2.resize(img_bgr, (new_w, new_h), interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_CUBIC)
            res = self._scan_mat(resized)
            if res:
                logs.append(f"Stage 2 Success: QR detected at scaled resolution {new_w}x{new_h}.")
                return res[0], None, logs

        # -------------------------------------------------------------
        # Stage 3: Rotational Scanning (90°, 180°, 270°)
        # Smartphone photos are frequently sideways or upside down
        # -------------------------------------------------------------
        rotations = [
            (cv2.ROTATE_90_CLOCKWISE, "90° CW"),
            (cv2.ROTATE_180, "180°"),
            (cv2.ROTATE_90_COUNTERCLOCKWISE, "270° CW")
        ]
        for rot_code, rot_name in rotations:
            rotated = cv2.rotate(img_bgr, rot_code)
            res = self._scan_mat(rotated)
            if res:
                logs.append(f"Stage 3 Success: QR detected after {rot_name} rotation.")
                return res[0], None, logs

        # -------------------------------------------------------------
        # Stage 4: Contrast & Adaptive Filtering (CLAHE & Sharpening)
        # Handles card lamination glare, shadows, and low contrast
        # -------------------------------------------------------------
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        res = self._scan_mat(enhanced)
        if res:
            logs.append("Stage 4 Success: QR detected after CLAHE contrast enhancement.")
            return res[0], None, logs

        # Sharpening
        kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
        sharpened = cv2.filter2D(enhanced, -1, kernel)
        res = self._scan_mat(sharpened)
        if res:
            logs.append("Stage 4 Success: QR detected after unsharp sharpening.")
            return res[0], None, logs

        # -------------------------------------------------------------
        # Stage 5: Aadhaar-Specific Quadrants & Region of Interest (ROI) Cropping
        # On Aadhaar cards:
        # - Aadhaar Card Back: Large QR code on the right side or bottom right
        # - Aadhaar Card Front: Small QR code on bottom left
        # - e-Aadhaar Sheet: Large QR code in bottom half
        # -------------------------------------------------------------
        h, w = img_bgr.shape[:2]
        rois = [
            ("Aadhaar Back (Bottom-Right)", img_bgr[int(h * 0.35):h, int(w * 0.35):w]),
            ("Aadhaar Back (Right-Half)", img_bgr[0:h, int(w * 0.40):w]),
            ("Aadhaar Front (Bottom-Left)", img_bgr[int(h * 0.35):h, 0:int(w * 0.65)]),
            ("e-Aadhaar Sheet (Lower-Half)", img_bgr[int(h * 0.40):h, 0:w]),
            ("Card Center Region", img_bgr[int(h * 0.2):int(h * 0.8), int(w * 0.2):int(w * 0.8)]),
            ("Upper Right", img_bgr[0:int(h * 0.65), int(w * 0.35):w]),
            ("Upper Left", img_bgr[0:int(h * 0.65), 0:int(w * 0.65)]),
        ]

        for roi_name, roi_mat in rois:
            if roi_mat.shape[0] < 50 or roi_mat.shape[1] < 50:
                continue
            # Try scanning ROI directly
            res = self._scan_mat(roi_mat)
            if res:
                logs.append(f"Stage 5 Success: QR detected in {roi_name} crop.")
                cropped_pil = Image.fromarray(cv2.cvtColor(roi_mat, cv2.COLOR_BGR2RGB))
                return res[0], cropped_pil, logs

            # Try upscaling the ROI
            rh, rw = roi_mat.shape[:2]
            scale_factor = 950.0 / max(rh, rw)
            if scale_factor > 1.2:
                scaled_roi = cv2.resize(roi_mat, (int(rw * scale_factor), int(rh * scale_factor)), interpolation=cv2.INTER_CUBIC)
                res = self._scan_mat(scaled_roi)
                if res:
                    logs.append(f"Stage 5 Success: QR detected in upscaled {roi_name}.")
                    cropped_pil = Image.fromarray(cv2.cvtColor(scaled_roi, cv2.COLOR_BGR2RGB))
                    return res[0], cropped_pil, logs

            # Try rotating the ROI
            for rot_code, rot_name in [(cv2.ROTATE_90_CLOCKWISE, "90°"), (cv2.ROTATE_90_COUNTERCLOCKWISE, "270°")]:
                rotated_roi = cv2.rotate(roi_mat, rot_code)
                res = self._scan_mat(rotated_roi)
                if res:
                    logs.append(f"Stage 5 Success: QR detected in rotated {roi_name} ({rot_name}).")
                    cropped_pil = Image.fromarray(cv2.cvtColor(rotated_roi, cv2.COLOR_BGR2RGB))
                    return res[0], cropped_pil, logs

        # -------------------------------------------------------------
        # Stage 6: Contour / Square Detection for Candidate QR Patches
        # -------------------------------------------------------------
        logs.append("Stage 6: Running contour quadrilateral detection for Aadhaar QR box...")
        try:
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            thresh = cv2.adaptiveThreshold(blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 19, 5)
            contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

            doc_area = w * h
            candidate_boxes = []

            for cnt in contours:
                area = cv2.contourArea(cnt)
                if 0.01 * doc_area < area < 0.45 * doc_area:
                    x, y, bw, bh = cv2.boundingRect(cnt)
                    aspect_ratio = float(bw) / float(bh)
                    if 0.75 <= aspect_ratio <= 1.35:
                        candidate_boxes.append((area, x, y, bw, bh))

            candidate_boxes.sort(key=lambda b: b[0], reverse=True)

            for _, x, y, bw, bh in candidate_boxes[:8]:
                pad_x = int(bw * 0.12)
                pad_y = int(bh * 0.12)
                x1 = max(0, x - pad_x)
                y1 = max(0, y - pad_y)
                x2 = min(w, x + bw + pad_x)
                y2 = min(h, y + bh + pad_y)

                patch = img_bgr[y1:y2, x1:x2]
                res = self._scan_mat(patch)
                if res:
                    logs.append(f"Stage 6 Success: Aadhaar QR detected via contour box at ({x1}, {y1}, {x2-x1}x{y2-y1}).")
                    cropped_pil = Image.fromarray(cv2.cvtColor(patch, cv2.COLOR_BGR2RGB))
                    return res[0], cropped_pil, logs
        except Exception as e:
            logs.append(f"Stage 6 contour search warning: {str(e)}")

        logs.append("All 6 stages completed: No Aadhaar QR code could be extracted from this card image.")
        return None, None, logs


# Backward compatibility alias
DocumentQRExtractor = AadhaarQRExtractor


# =====================================================================
# 2. Aadhaar QR Code Parser
# =====================================================================

def parse_aadhaar_qr(raw_qr_data: str) -> Dict[str, Any]:
    """
    Specifically parses Aadhaar QR code data (Secure numeric QR or Old XML QR).
    Returns normalized dictionary of Aadhaar identity fields.
    """
    raw_str = str(raw_qr_data).strip()
    result = {
        'doc_type': 'UNKNOWN',
        'name': '',
        'dob': '',
        'gender': '',
        'aadhaar_last_4_digit': '',
        'care_of': '',
        'pincode': '',
        'address': '',
        'raw_fields': {},
        'has_photo': False,
        'photo_base64': None
    }

    # Case A: Aadhaar Secure QR (Numeric / Gzip compressed)
    if isSecureQr(raw_str):
        result['doc_type'] = 'AADHAAR_SECURE_QR'
        obj = AadhaarSecureQr(raw_str)
        data = obj.decodeddata()
        result['raw_fields'] = data
        result['name'] = data.get('name', '')
        result['dob'] = data.get('dob', '')
        result['gender'] = data.get('gender', '')
        result['care_of'] = data.get('careof', '')
        result['pincode'] = data.get('pincode', '')
        result['aadhaar_last_4_digit'] = data.get('aadhaar_last_4_digit', '')

        # Assemble full address
        addr_keys = ['house', 'street', 'landmark', 'location', 'vtc', 'subdistrict', 'district', 'state', 'pincode']
        parts = [data[k] for k in addr_keys if data.get(k) and data[k] != '-']
        result['address'] = ', '.join(parts)

        if obj.isImage():
            img = obj.image()
            if img:
                result['has_photo'] = True
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=90)
                import base64
                result['photo_base64'] = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode('utf-8')

        return result

    # Case B: Aadhaar Old XML QR
    if '<PrintLetterBarcodeData' in raw_str:
        result['doc_type'] = 'AADHAAR_OLD_XML_QR'
        obj = AadhaarOldQr(raw_str)
        data = obj.decodeddata()
        result['raw_fields'] = data
        result['name'] = data.get('name', '')
        result['dob'] = data.get('dob', '') or data.get('yob', '')
        result['gender'] = data.get('gender', '')
        uid = data.get('uid', '')
        result['aadhaar_last_4_digit'] = uid[-4:] if len(uid) >= 4 else uid
        result['care_of'] = data.get('co', '') or data.get('gname', '')
        result['pincode'] = data.get('pc', '')

        addr_keys = ['house', 'street', 'lm', 'loc', 'vtc', 'po', 'subdist', 'dist', 'state', 'pc']
        parts = [data[k] for k in addr_keys if data.get(k) and data[k] != '-']
        result['address'] = ', '.join(parts)
        return result

    result['raw_fields'] = {'raw_text': raw_str}
    return result


# Backward compatibility alias
parse_document_qr = parse_aadhaar_qr


# =====================================================================
# 3. Aadhaar Details Normalizer & Matching Engine
# =====================================================================

class AadhaarDetailsMatcher:
    """
    Intelligently compares and reconciles user-filled Aadhaar form details
    against decoded QR data from the Aadhaar card.
    """

    @staticmethod
    def normalize_text(text: Optional[str]) -> str:
        """Strip prefixes, punctuation, and extra whitespace."""
        if not text:
            return ""
        s = str(text).lower()
        s = re.sub(r'\b(mr|mrs|ms|shri|smt|dr|s/o|d/o|w/o|c/o|c/o:|s/o:)\b', ' ', s)
        s = re.sub(r'[^\w\s]', ' ', s)
        return ' '.join(s.split())

    @staticmethod
    def normalize_date(d_str: Optional[str]) -> str:
        """Parse various date formats to ISO YYYY-MM-DD or 4-digit Year."""
        if not d_str:
            return ""
        s = str(d_str).strip()
        formats = [
            '%d-%m-%Y', '%d/%m/%Y', '%d.%m.%Y',
            '%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d',
            '%d-%b-%Y', '%d %b %Y', '%d-%B-%Y', '%d %B %Y'
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                pass
        # Extract 4-digit year
        m = re.search(r'\b(19\d{2}|20\d{2})\b', s)
        if m:
            return m.group(1)
        return s

    @staticmethod
    def normalize_gender(g_str: Optional[str]) -> str:
        if not g_str:
            return ""
        s = str(g_str).strip().lower()
        if s in ('m', 'male', 'purush', 'man'):
            return 'M'
        if s in ('f', 'female', 'mahila', 'woman'):
            return 'F'
        if s in ('t', 'transgender', 'other'):
            return 'T'
        return s.upper()

    @staticmethod
    def string_similarity(s1: str, s2: str) -> float:
        """Token sort ratio + SequenceMatcher similarity."""
        if not s1 or not s2:
            return 0.0
        n1 = AadhaarDetailsMatcher.normalize_text(s1)
        n2 = AadhaarDetailsMatcher.normalize_text(s2)
        if n1 == n2:
            return 1.0

        t1 = ' '.join(sorted(n1.split()))
        t2 = ' '.join(sorted(n2.split()))
        if t1 == t2:
            return 1.0

        ratio = difflib.SequenceMatcher(None, t1, t2).ratio()
        return round(ratio, 3)

    def match(
        self,
        decoded_qr: Dict[str, Any],
        filled_details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Reconcile decoded Aadhaar QR details with user-filled details.
        Returns full match evaluation report with scores, field status, and verdict.
        """
        field_evals = {}
        weighted_scores = []
        weights = []

        # -----------------------------
        # 1. Full Name Matching (Weight: 35)
        # -----------------------------
        filled_name = filled_details.get('name', '').strip()
        qr_name = decoded_qr.get('name', '').strip()
        if filled_name:
            if qr_name:
                sim = self.string_similarity(filled_name, qr_name)
                status = 'MATCH' if sim >= 0.85 else ('PARTIAL_MATCH' if sim >= 0.60 else 'MISMATCH')
                field_evals['name'] = {
                    'label': 'Full Name',
                    'filled': filled_name,
                    'qr_value': qr_name,
                    'status': status,
                    'score': int(sim * 100),
                    'detail': f"{int(sim * 100)}% Name match similarity"
                }
                weighted_scores.append(sim * 35)
                weights.append(35)
            else:
                field_evals['name'] = {
                    'label': 'Full Name',
                    'filled': filled_name,
                    'qr_value': 'Not Present in QR',
                    'status': 'NOT_IN_QR',
                    'score': 0,
                    'detail': 'Name not found in QR code'
                }

        # -----------------------------
        # 2. Date of Birth Matching (Weight: 25)
        # -----------------------------
        filled_dob = filled_details.get('dob', '').strip()
        qr_dob = decoded_qr.get('dob', '').strip()
        if filled_dob:
            if qr_dob:
                norm_filled = self.normalize_date(filled_dob)
                norm_qr = self.normalize_date(qr_dob)
                if norm_filled == norm_qr:
                    sim = 1.0
                    status = 'MATCH'
                    msg = 'Exact Date of Birth match'
                elif len(norm_filled) == 4 or len(norm_qr) == 4:
                    sim = 0.85 if norm_filled[-4:] == norm_qr[-4:] else 0.0
                    status = 'PARTIAL_MATCH' if sim > 0 else 'MISMATCH'
                    msg = 'Year of Birth matches' if sim > 0 else 'Year does not match'
                else:
                    sim = 0.0
                    status = 'MISMATCH'
                    msg = 'Date of birth mismatch'

                field_evals['dob'] = {
                    'label': 'Date of Birth',
                    'filled': filled_dob,
                    'qr_value': qr_dob,
                    'status': status,
                    'score': int(sim * 100),
                    'detail': msg
                }
                weighted_scores.append(sim * 25)
                weights.append(25)
            else:
                field_evals['dob'] = {
                    'label': 'Date of Birth',
                    'filled': filled_dob,
                    'qr_value': 'Not Present in QR',
                    'status': 'NOT_IN_QR',
                    'score': 0,
                    'detail': 'DOB not found in QR'
                }

        # -----------------------------
        # 3. Aadhaar Number (Weight: 25)
        # Matches last 4 digits against decoded Aadhaar last 4 digits
        # -----------------------------
        filled_id = filled_details.get('id_number', '').strip().replace(' ', '').replace('-', '')
        qr_last4 = decoded_qr.get('aadhaar_last_4_digit', '').strip()
        if filled_id:
            if qr_last4:
                last4_filled = filled_id[-4:]
                is_match = (last4_filled == qr_last4)
                sim = 1.0 if is_match else 0.0
                status = 'MATCH' if is_match else 'MISMATCH'
                msg = f"Last 4 digits match ({qr_last4})" if is_match else f"Mismatch (Expected last 4 digits: {qr_last4}, provided: {last4_filled})"

                field_evals['id_number'] = {
                    'label': 'Aadhaar Number',
                    'filled': f"XXXX XXXX {last4_filled}",
                    'qr_value': f"XXXX XXXX {qr_last4}",
                    'status': status,
                    'score': int(sim * 100),
                    'detail': msg
                }
                weighted_scores.append(sim * 25)
                weights.append(25)
            else:
                field_evals['id_number'] = {
                    'label': 'Aadhaar Number',
                    'filled': filled_id,
                    'qr_value': 'Not Present in QR',
                    'status': 'NOT_IN_QR',
                    'score': 0,
                    'detail': 'Aadhaar number not in QR'
                }

        # -----------------------------
        # 4. Gender (Weight: 10)
        # -----------------------------
        filled_gender = filled_details.get('gender', '').strip()
        qr_gender = decoded_qr.get('gender', '').strip()
        if filled_gender and qr_gender:
            g1 = self.normalize_gender(filled_gender)
            g2 = self.normalize_gender(qr_gender)
            is_match = (g1 == g2)
            sim = 1.0 if is_match else 0.0
            field_evals['gender'] = {
                'label': 'Gender',
                'filled': filled_gender,
                'qr_value': qr_gender,
                'status': 'MATCH' if is_match else 'MISMATCH',
                'score': int(sim * 100),
                'detail': 'Gender matches' if is_match else 'Gender mismatch'
            }
            weighted_scores.append(sim * 10)
            weights.append(10)

        # -----------------------------
        # 5. Care Of / Father's Name (Weight: 10)
        # -----------------------------
        filled_careof = filled_details.get('care_of', '').strip()
        qr_careof = decoded_qr.get('care_of', '').strip()
        if filled_careof and qr_careof:
            sim = self.string_similarity(filled_careof, qr_careof)
            status = 'MATCH' if sim >= 0.80 else ('PARTIAL_MATCH' if sim >= 0.50 else 'MISMATCH')
            field_evals['care_of'] = {
                'label': 'Care Of / Guardian',
                'filled': filled_careof,
                'qr_value': qr_careof,
                'status': status,
                'score': int(sim * 100),
                'detail': f"{int(sim * 100)}% Care Of name match"
            }
            weighted_scores.append(sim * 10)
            weights.append(10)

        # -----------------------------
        # 6. Pincode (Weight: 5)
        # -----------------------------
        filled_pin = filled_details.get('pincode', '').strip()
        qr_pin = decoded_qr.get('pincode', '').strip()
        if filled_pin and qr_pin:
            is_match = (filled_pin == qr_pin)
            sim = 1.0 if is_match else 0.0
            field_evals['pincode'] = {
                'label': 'Pincode',
                'filled': filled_pin,
                'qr_value': qr_pin,
                'status': 'MATCH' if is_match else 'MISMATCH',
                'score': int(sim * 100),
                'detail': 'Pincode matches' if is_match else 'Pincode mismatch'
            }
            weighted_scores.append(sim * 5)
            weights.append(5)

        # -----------------------------
        # Overall Score & Verdict
        # -----------------------------
        total_weight = sum(weights) if weights else 1
        overall_score = round((sum(weighted_scores) / total_weight) * 100) if weights else 0

        # Check for critical mismatches
        name_eval = field_evals.get('name', {})
        dob_eval = field_evals.get('dob', {})
        id_eval = field_evals.get('id_number', {})

        critical_mismatch = (
            name_eval.get('status') == 'MISMATCH' or
            dob_eval.get('status') == 'MISMATCH' or
            id_eval.get('status') == 'MISMATCH'
        )

        if overall_score >= 80 and not critical_mismatch:
            verdict = 'VERIFIED'
            verdict_badge = '✅ Aadhaar Verified (High Confidence)'
            summary = f"Aadhaar card details match the provided information with {overall_score}% confidence score. All key identity attributes align."
        elif overall_score >= 55:
            verdict = 'PARTIAL_MATCH'
            verdict_badge = '⚠️ Partial Match (Review Recommended)'
            summary = f"Partial Aadhaar match ({overall_score}%). Some details align, but one or more fields require manual review."
        else:
            verdict = 'REJECTED'
            verdict_badge = '❌ Aadhaar Mismatch / Rejected'
            summary = f"Verification failed with a match score of {overall_score}%. Significant discrepancies detected between Aadhaar QR and form data."

        return {
            'doc_type': decoded_qr.get('doc_type', 'AADHAAR'),
            'overall_score': overall_score,
            'verdict': verdict,
            'verdict_badge': verdict_badge,
            'summary': summary,
            'field_evaluations': field_evals,
            'decoded_qr': decoded_qr
        }


# Backward compatibility alias
DocumentDetailsMatcher = AadhaarDetailsMatcher


# =====================================================================
# Standalone CLI / Self-Test
# =====================================================================

if __name__ == '__main__':
    print("=" * 65)
    print("  PyAadhaar Document QR Extractor & Details Matcher")
    print("=" * 65)

    from PIL import ImageDraw
    import gzip

    print("\n[1] Generating simulated full Aadhaar card with embedded QR...")
    payload = "3\xff12342024102890441258\xffVikram Malhotra\xff14-07-1988\xffM\xffS/O: Suresh Malhotra\xffMumbai\xffMarine Drive\xffFlat 12\xffNariman Pt\xff400021\xffGPO\xffMaharashtra\xffMG Road\xffSouth Mumbai\xffMumbai\xff"
    compressed = gzip.compress(payload.encode('ISO-8859-1') + (b'\x01' * 200) + (b'\x22' * 256))
    big_int_str = str(int.from_bytes(compressed, 'big'))

    if HAS_ZXING and zxingcpp is not None:
        bc = zxingcpp.create_barcode(big_int_str, zxingcpp.BarcodeFormat.QRCode)
        qr_arr = zxingcpp.write_barcode_to_image(bc)
        qr_pil = Image.fromarray(qr_arr).resize((300, 300), Image.NEAREST)

        # Full card image (1200 x 800)
        card = Image.new('RGB', (1200, 800), color=(255, 255, 255))
        draw = ImageDraw.Draw(card)
        draw.rectangle([0, 0, 1200, 24], fill=(255, 153, 51))
        draw.rectangle([0, 24, 1200, 36], fill=(19, 136, 8))
        draw.text((60, 100), "GOVERNMENT OF INDIA / भारत सरकार", fill=(0, 0, 0))
        draw.text((60, 140), "Name: Vikram Malhotra", fill=(0, 0, 0))
        draw.text((60, 180), "DOB: 14/07/1988", fill=(0, 0, 0))
        draw.text((60, 220), "Gender: Male", fill=(0, 0, 0))
        draw.text((60, 300), "XXXX XXXX 1234", fill=(0, 0, 128))
        card.paste(qr_pil, (860, 460))

        # Test extraction
        extractor = AadhaarQRExtractor()
        raw_qr, cropped, logs = extractor.extract_qr_from_document(card)
        print("Extraction Result:", "SUCCESS" if raw_qr else "FAILED")
        for log in logs:
            print("  >", log)

        assert raw_qr is not None, "QR code extraction should succeed"

        # Test parsing
        parsed = parse_aadhaar_qr(raw_qr)
        print("\n[2] Parsed Aadhaar QR Data:")
        print("  Doc Type:", parsed['doc_type'])
        print("  Name:", parsed['name'])
        print("  DOB:", parsed['dob'])
        print("  Aadhaar Last 4:", parsed['aadhaar_last_4_digit'])

        # Test matching against filled details
        print("\n[3] Testing Aadhaar Details Reconciliation...")
        matcher = AadhaarDetailsMatcher()
        filled_form = {
            'name': 'Vikram Malhotra',
            'dob': '1988-07-14',
            'gender': 'Male',
            'id_number': 'XXXX XXXX 1234',
            'pincode': '400021'
        }
        report = matcher.match(parsed, filled_form)
        print(f"  Overall Score: {report['overall_score']}%")
        print(f"  Verdict: {report['verdict']}")
        print(f"  Summary: {report['summary']}")

        assert report['verdict'] == 'VERIFIED'
        assert report['overall_score'] == 100
        print("\n>>> ALL AADHAAR VERIFIER TESTS PASSED 100%! <<<")
    else:
        print("zxing-cpp required for self-test.")
