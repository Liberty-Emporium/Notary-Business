#!/usr/bin/env python3
"""
NotaryPro — Remote Online Notary Platform
NC RON (Remote Online Notarization) Compliant
"""

import os
import io
import json
import uuid
import base64
import hashlib
import secrets
import datetime
from functools import wraps

import jwt
import stripe
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_file, send_from_directory)
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable, PageBreak, Image as RLImage)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF

# ── App Config ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')

# Data directories
DATA_DIR = os.environ.get('RAILWAY_DATA_DIR', '/data')
APP_DATA = os.path.join(DATA_DIR, 'notary_app')
os.makedirs(APP_DATA, exist_ok=True)

SESSIONS_DIR = os.path.join(APP_DATA, 'sessions')
DOCS_DIR = os.path.join(APP_DATA, 'documents')
SIGS_DIR = os.path.join(APP_DATA, 'signatures')
os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(SIGS_DIR, exist_ok=True)

# ── Notary Config (filled by admin) ─────────────────────────────────────────
NOTARY_CONFIG_FILE = os.path.join(APP_DATA, 'notary_config.json')

def load_notary_config():
    if os.path.exists(NOTARY_CONFIG_FILE):
        with open(NOTARY_CONFIG_FILE) as f:
            return json.load(f)
    return {
        'name': '',
        'commission_number': '',
        'commission_expires': '',
        'county': '',
        'state': 'North Carolina',
        'fee_per_signature': 25,
        'fee_multi_signature': 10,
        'stripe_account_id': '',
        'business_name': '',
        'business_email': '',
        'business_phone': '',
    }

def save_notary_config(config):
    with open(NOTARY_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

# ── Database helpers ────────────────────────────────────────────────────────
JOURNAL_FILE = os.path.join(APP_DATA, 'journal.json')

def load_journal():
    if os.path.exists(JOURNAL_FILE):
        with open(JOURNAL_FILE) as f:
            return json.load(f)
    return []

def save_journal(entries):
    with open(JOURNAL_FILE, 'w') as f:
        json.dump(entries, f, indent=2)

def add_journal_entry(entry):
    journal = load_journal()
    entry['id'] = str(uuid.uuid4())[:8]
    entry['timestamp'] = datetime.datetime.utcnow().isoformat()
    journal.append(entry)
    save_journal(journal)
    return entry

# ── Session helpers ─────────────────────────────────────────────────────────
def save_session_data(sid, data):
    path = os.path.join(SESSIONS_DIR, f'{sid}.json')
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def load_session_data(sid):
    path = os.path.join(SESSIONS_DIR, f'{sid}.json')
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def save_signature_image(data_url, session_id, signer_name):
    """Save a base64 signature image to disk."""
    header, encoded = data_url.split(',', 1)
    img_data = base64.b64decode(encoded)
    ext = 'png'
    if 'jpeg' in header or 'jpg' in header:
        ext = 'jpg'
    sig_name = f"{session_id}_{signer_name}.{ext}"
    sig_path = os.path.join(SIGS_DIR, sig_name)
    with open(sig_path, 'wb') as f:
        f.write(img_data)
    return sig_path

def save_document(file_bytes, session_id, filename):
    """Save uploaded document."""
    safe_name = filename.replace(' ', '_').replace('/', '_')
    doc_name = f"{session_id}_{safe_name}"
    doc_path = os.path.join(DOCS_DIR, doc_name)
    with open(doc_path, 'wb') as f:
        f.write(file_bytes)
    return doc_path, doc_name

# ── Decorators ──────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Routes: Public ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    config = load_notary_config()
    return render_template('index.html', config=config)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        stored = os.environ.get('ADMIN_PASSWORD', 'notary2025')
        if pw == stored:
            session['authenticated'] = True
            session.permanent = True
            return redirect(url_for('dashboard'))
        error = 'Wrong password.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('index'))

# ── Routes: Dashboard ───────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    config = load_notary_config()
    journal = load_journal()
    sessions = []
    for f in os.listdir(SESSIONS_DIR):
        if f.endswith('.json'):
            data = load_session_data(f.replace('.json', ''))
            if data:
                sessions.append(data)
    sessions.sort(key=lambda x: x.get('created', ''), reverse=True)
    return render_template('dashboard.html', config=config, journal=journal[-20:],
                           sessions=sessions[:10])

# ── Routes: Session Management ──────────────────────────────────────────────

@app.route('/session/new', methods=['POST'])
@login_required
def new_session():
    """Create a new notarization session."""
    data = request.form
    sid = str(uuid.uuid4())[:12]
    session_data = {
        'id': sid,
        'created': datetime.datetime.utcnow().isoformat(),
        'status': 'preparing',
        'signer_name': data.get('signer_name', ''),
        'signer_email': data.get('signer_email', ''),
        'document_type': data.get('document_type', ''),
        'num_signatures': int(data.get('num_signatures', 1)),
        'notes': data.get('notes', ''),
        'signatures': {},
        'id_verified': False,
        'kba_passed': False,
        'video_recorded': False,
        'payment_status': 'pending',
        'document_path': None,
        'document_name': None,
    }
    save_session_data(sid, session_data)
    return redirect(url_for('session_view', sid=sid))

@app.route('/session/new')
@login_required
def session_new():
    return render_template('session_new.html')

@app.route('/session/<sid>')
@login_required
def session_view(sid):
    """View a notarization session."""
    data = load_session_data(sid)
    if not data:
        flash('Session not found.')
        return redirect(url_for('dashboard'))
    config = load_notary_config()
    return render_template('session.html', session=data, config=config)

@app.route('/session/<sid>/upload', methods=['POST'])
@login_required
def upload_document(sid):
    """Upload a document for notarization."""
    data = load_session_data(sid)
    if not data:
        return jsonify({'error': 'Session not found'}), 404

    if 'document' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['document']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_bytes = file.read()
    doc_path, doc_name = save_document(file_bytes, sid, file.filename)
    data['document_path'] = doc_path
    data['document_name'] = doc_name
    data['status'] = 'ready'
    save_session_data(sid, data)

    return jsonify({'status': 'uploaded', 'filename': doc_name})

@app.route('/session/<sid>/sign', methods=['POST'])
@login_required
def save_signature(sid):
    """Save a signature for a session."""
    data = load_session_data(sid)
    if not data:
        return jsonify({'error': 'Session not found'}), 404

    body = request.get_json(force=True) or {}
    signer = body.get('signer', 'signer')
    sig_data = body.get('signature', '')
    signed_date = body.get('date', datetime.datetime.now().strftime('%B %d, %Y'))

    if not sig_data:
        return jsonify({'error': 'No signature data'}), 400

    sig_path = save_signature_image(sig_data, sid, signer)
    data['signatures'][signer] = {
        'path': sig_path,
        'date': signed_date,
    }
    save_session_data(sid, data)

    return jsonify({'status': 'signed', 'signer': signer})

@app.route('/session/<sid>/update', methods=['POST'])
@login_required
def update_session(sid):
    """Update session status/fields."""
    data = load_session_data(sid)
    if not data:
        return jsonify({'error': 'Session not found'}), 404

    body = request.get_json(force=True) or {}
    for field in ['status', 'id_verified', 'kba_passed', 'video_recorded', 'payment_status']:
        if field in body:
            data[field] = body[field]
    save_session_data(sid, data)
    return jsonify({'status': 'updated'})

@app.route('/session/<sid>/complete', methods=['POST'])
@login_required
def complete_session(sid):
    """Complete the notarization and generate final PDF."""
    data = load_session_data(sid)
    if not data:
        return jsonify({'error': 'Session not found'}), 404

    config = load_notary_config()

    # Generate notarized PDF
    pdf_path = generate_notarized_pdf(data, config)
    data['status'] = 'completed'
    data['completed_at'] = datetime.datetime.utcnow().isoformat()
    data['final_pdf'] = pdf_path
    save_session_data(sid, data)

    # Add to journal
    add_journal_entry({
        'session_id': sid,
        'signer_name': data.get('signer_name', ''),
        'document_type': data.get('document_type', ''),
        'num_signatures': len(data.get('signatures', {})),
        'fee': config.get('fee_per_signature', 25) * len(data.get('signatures', {})),
        'status': 'completed',
    })

    return jsonify({'status': 'completed', 'pdf_path': pdf_path})

# ── Routes: Settings ────────────────────────────────────────────────────────

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    config = load_notary_config()
    if request.method == 'POST':
        for key in config:
            if key in request.form:
                config[key] = request.form[key]
        # Handle numeric fields
        for key in ['fee_per_signature', 'fee_multi_signature']:
            if key in request.form:
                try:
                    config[key] = float(request.form[key])
                except ValueError:
                    pass
        save_notary_config(config)
        flash('Settings saved!')
        return redirect(url_for('settings'))
    return render_template('settings.html', config=config)

# ── Routes: Journal ─────────────────────────────────────────────────────────

@app.route('/journal')
@login_required
def journal():
    entries = load_journal()
    entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return render_template('journal.html', entries=entries)

@app.route('/api/journal')
@login_required
def api_journal():
    entries = load_journal()
    return jsonify(entries)

# ── PDF Generation ──────────────────────────────────────────────────────────

def generate_notarized_pdf(session_data, config):
    """Generate a notarized PDF with signatures, seal, and notary certificate."""
    doc_path = session_data.get('document_path')
    if not doc_path or not os.path.exists(doc_path):
        return None

    output_path = os.path.join(DOCS_DIR, f"{session_data['id']}_notarized.pdf")

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch,
    )
    styles = getSampleStyleSheet()
    NAVY = HexColor('#1A237E')
    GOLD = HexColor('#D4AF37')
    story = []

    # Try to import original PDF pages
    try:
        from PyPDF2 import PdfReader, PdfWriter
        reader = PdfReader(doc_path)
        # We'll add the original pages plus a notary certificate page
        # For now, create a notary certificate page
        pass
    except ImportError:
        pass

    # ── Notary Certificate Page ──────────────────────────────────────────
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("NOTARY ACKNOWLEDGMENT",
        ParagraphStyle('NC', parent=styles['Title'], fontSize=16, textColor=NAVY,
                       alignment=TA_CENTER, fontName='Helvetica-Bold')))
    story.append(HRFlowable(width="60%", thickness=1, color=GOLD, spaceAfter=16, spaceBefore=6))

    # State and county
    story.append(Paragraph(
        f"State of {config.get('state', 'North Carolina')}",
        ParagraphStyle('S1', parent=styles['Normal'], fontSize=11, textColor=black,
                       alignment=TA_LEFT, fontName='Helvetica')))
    story.append(Paragraph(
        f"County of {config.get('county', '_______________')}",
        ParagraphStyle('S2', parent=styles['Normal'], fontSize=11, textColor=black,
                       alignment=TA_LEFT, fontName='Helvetica')))
    story.append(Spacer(1, 0.2*inch))

    # Notary statement
    signer_name = session_data.get('signer_name', '_________________')
    doc_type = session_data.get('document_type', '_________________')
    today = datetime.datetime.now().strftime('%B %d, %Y')

    story.append(Paragraph(
        f"On this <b>{today}</b>, before me, <b>{config.get('name', '_________________')}</b>, "
        f"Notary Public for said State, personally appeared <b>{signer_name}</b>, "
        f"known to me (or proved to me on the basis of satisfactory evidence) to be the person "
        f"whose name is subscribed to the within instrument and acknowledged to me that they "
        f"executed the same in their authorized capacity.",
        ParagraphStyle('S3', parent=styles['Normal'], fontSize=10, textColor=black,
                       alignment=TA_JUSTIFY, leading=14, fontName='Helvetica')))
    story.append(Spacer(1, 0.3*inch))

    # Signature lines
    for signer_name_key, sig_info in session_data.get('signatures', {}).items():
        sig_path = sig_info.get('path', '')
        sig_date = sig_info.get('date', '_________________')
        if sig_path and os.path.exists(sig_path):
            sig_img = RLImage(sig_path, width=2.5*inch, height=0.6*inch, kind='proportional')
            story.append(sig_img)
        story.append(Paragraph(f"Signature of {signer_name_key}",
            ParagraphStyle('SL', parent=styles['Normal'], fontSize=8, textColor=HexColor('#666'),
                           fontName='Helvetica')))
        story.append(Paragraph(f"Date: {sig_date}",
            ParagraphStyle('SD', parent=styles['Normal'], fontSize=8, textColor=HexColor('#666'),
                           fontName='Helvetica')))
        story.append(Spacer(1, 0.15*inch))

    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#ccc'), spaceAfter=10))

    # Notary seal area
    seal_data = [[
        Paragraph(f"<b>{config.get('name', 'NOTARY PUBLIC')}</b><br/>"
                  f"Commission #{config.get('commission_number', '________')}<br/>"
                  f"Expires: {config.get('commission_expires', '________')}<br/>"
                  f"{config.get('county', '_______')} County, {config.get('state', 'NC')}",
            ParagraphStyle('SE', parent=styles['Normal'], fontSize=9, textColor=black,
                           alignment=TA_CENTER, fontName='Helvetica')),
    ]]
    seal_table = Table(seal_data, colWidths=[3*inch])
    seal_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1.5, NAVY),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F5F5FA')),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(seal_table)

    # Notary signature line
    story.append(Spacer(1, 0.3*inch))
    notary_sig_path = session_data.get('signatures', {}).get('notary', {}).get('path', '')
    if notary_sig_path and os.path.exists(notary_sig_path):
        story.append(RLImage(notary_sig_path, width=2.5*inch, height=0.5*inch, kind='proportional'))
    story.append(HRFlowable(width="40%", thickness=0.5, color=black, spaceBefore=2))
    story.append(Paragraph("Notary Public Signature",
        ParagraphStyle('NS', parent=styles['Normal'], fontSize=8, textColor=HexColor('#666'),
                       alignment=TA_CENTER, fontName='Helvetica')))

    doc.build(story)

    # Merge with original PDF if PyPDF2 available
    try:
        from PyPDF2 import PdfReader, PdfWriter
        writer = PdfWriter()
        # Add original pages
        reader = PdfReader(doc_path)
        for page in reader.pages:
            writer.add_page(page)
        # Add notary certificate
        cert_reader = PdfReader(output_path)
        for page in cert_reader.pages:
            writer.add_page(page)
        # Write merged
        with open(output_path, 'wb') as f:
            writer.write(f)
    except ImportError:
        pass

    return output_path

@app.route('/session/<sid>/download')
@login_required
def download_pdf(sid):
    """Download the notarized PDF."""
    data = load_session_data(sid)
    if not data or not data.get('final_pdf'):
        flash('PDF not ready yet.')
        return redirect(url_for('session_view', sid=sid))
    return send_file(data['final_pdf'], mimetype='application/pdf',
                     download_name=f'notarized_{sid}.pdf')

# ── API: Signature image retrieval ──────────────────────────────────────────

@app.route('/signature/<sid>/<signer>')
def get_signature(sid, signer):
    """Serve a signature image."""
    sig_name = f"{sid}_{signer}.png"
    sig_path = os.path.join(SIGS_DIR, sig_name)
    if not os.path.exists(sig_path):
        sig_name = f"{sid}_{signer}.jpg"
        sig_path = os.path.join(SIGS_DIR, sig_name)
    if os.path.exists(sig_path):
        return send_file(sig_path, mimetype='image/png')
    return jsonify({'error': 'Not found'}), 404

# ── Run ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)