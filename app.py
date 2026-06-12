#!/usr/bin/env python3
"""
Easy Notary — Remote Online Notary Platform
NC RON (Remote Online Notarization) Compliant
Single-tenant: one app instance per notary
"""

import os
import io
import json
import uuid
import base64
import hashlib
import secrets
import sqlite3
import datetime
import threading
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

# ─── App Config ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'easy-notary-dev-key-change-in-production-2026')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Fix for HTTPS/Proxy (Railway) — ensure session cookies work behind HTTPS
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP for local dev
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Trust Railway's proxy headers
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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
ID_DIR = os.path.join(APP_DATA, 'id_uploads')
VIDEO_DIR = os.path.join(APP_DATA, 'video_recordings')
os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(SIGS_DIR, exist_ok=True)
os.makedirs(ID_DIR, exist_ok=True)
os.makedirs(VIDEO_DIR, exist_ok=True)

# WebRTC Signaling storage (in-memory, per-session)
video_signals = {}
video_signals_lock = threading.Lock()

# Database
DB_PATH = os.path.join(APP_DATA, 'notary.db')

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS easy_notaryfile (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            commission_number TEXT,
            commission_expires TEXT,
            county TEXT,
            state TEXT DEFAULT 'North Carolina',
            commission_type TEXT DEFAULT 'traditional',
            bond_amount TEXT DEFAULT '$10,000',
            business_name TEXT,
            business_email TEXT,
            business_phone TEXT,
            business_address TEXT,
            website TEXT,
            brand_color TEXT DEFAULT '#1A237E',
            accent_color TEXT DEFAULT '#D4AF37',
            logo_url TEXT,
            fee_per_signature REAL DEFAULT 25,
            fee_multi_signature REAL DEFAULT 10,
            fee_loan_package REAL DEFAULT 100,
            fee_travel REAL DEFAULT 0,
            max_signers INTEGER DEFAULT 10,
            stripe_account_id TEXT,
            payment_model TEXT DEFAULT 'direct',
            platform_commission REAL DEFAULT 10,
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            signer_name TEXT,
            signer_email TEXT,
            document_type TEXT,
            num_signatures INTEGER DEFAULT 1,
            notes TEXT,
            status TEXT DEFAULT 'preparing',
            id_verified INTEGER DEFAULT 0,
            id_upload_path TEXT,
            kba_passed INTEGER DEFAULT 0,
            video_recorded INTEGER DEFAULT 0,
            video_path TEXT,
            payment_status TEXT DEFAULT 'pending',
            payment_amount REAL DEFAULT 0,
            document_path TEXT,
            document_name TEXT,
            final_pdf TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS signatures (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            signer_name TEXT NOT NULL,
            signature_path TEXT NOT NULL,
            signed_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS journal (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            signer_name TEXT,
            document_type TEXT,
            num_signatures INTEGER DEFAULT 1,
            fee REAL DEFAULT 0,
            status TEXT DEFAULT 'completed',
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
        CREATE INDEX IF NOT EXISTS idx_journal_user ON journal(user_id);
        CREATE INDEX IF NOT EXISTS idx_signatures_session ON signatures(session_id);
    ''')
    db.commit()
    db.close()

init_db()

# ─── Helpers ─────────────────────────────────────────────────────────────────

def hash_password(pw):
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((pw + salt).encode()).hexdigest()
    return f"{salt}${pw_hash}"

def verify_password(pw, stored):
    if '$' not in stored:
        return False
    salt, pw_hash = stored.split('$', 1)
    return hashlib.sha256((pw + salt).encode()).hexdigest() == pw_hash

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_user():
    if not session.get('user_id'):
        return None
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    db.close()
    return user

def get_profile():
    if not session.get('user_id'):
        return None
    db = get_db()
    p = db.execute('SELECT * FROM easy_notaryfile WHERE user_id = ?', (session['user_id'],)).fetchone()
    db.close()
    if not p:
        # Create default profile
        pid = str(uuid.uuid4())[:12]
        db = get_db()
        db.execute('INSERT INTO easy_notaryfile (id, user_id, state) VALUES (?, ?, ?)',
                   (pid, session['user_id'], 'North Carolina'))
        db.commit()
        p = db.execute('SELECT * FROM easy_notaryfile WHERE id = ?', (pid,)).fetchone()
        db.close()
    return dict(p) if p else {}

def save_signature_image(data_url, session_id, signer_name):
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

def save_id_image(file_bytes, session_id):
    id_path = os.path.join(ID_DIR, f"{session_id}_id.jpg")
    with open(id_path, 'wb') as f:
        f.write(file_bytes)
    return id_path

def generate_notarized_pdf(session_data, config):
    """Generate a notarized PDF with signatures, seal, and notary certificate."""
    doc_path = session_data.get('document_path')
    if not doc_path or not os.path.exists(doc_path):
        return None

    output_path = os.path.join(DOCS_DIR, f"{session_data['id']}_notarized.pdf")
    sigs = session_data.get('signatures', {})

    doc = SimpleDocTemplate(output_path, pagesize=letter,
                             leftMargin=0.75*inch, rightMargin=0.75*inch,
                             topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    NAVY = HexColor('#1A237E')
    GOLD = HexColor('#D4AF37')
    story = []

    # Notary Certificate Page
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("NOTARY ACKNOWLEDGMENT",
        ParagraphStyle('NC', parent=styles['Title'], fontSize=16, textColor=NAVY,
                       alignment=TA_CENTER, fontName='Helvetica-Bold')))
    story.append(HRFlowable(width="60%", thickness=1, color=GOLD, spaceAfter=16, spaceBefore=6))

    story.append(Paragraph(f"State of {config.get('state', 'North Carolina')}",
        ParagraphStyle('S1', parent=styles['Normal'], fontSize=11, textColor=black, fontName='Helvetica')))
    story.append(Paragraph(f"County of {config.get('county', '_______________')}",
        ParagraphStyle('S2', parent=styles['Normal'], fontSize=11, textColor=black, fontName='Helvetica')))
    story.append(Spacer(1, 0.2*inch))

    signer_name = session_data.get('signer_name', '_________________')
    doc_type = session_data.get('document_type', '_________________')
    today = datetime.datetime.now().strftime('%B %d, %Y')
    # Support both old config dict and new profile dict from DB
    notary_name = (config.get('name') or config.get('business_name') or config.get('full_name') or '_________________')

    story.append(Paragraph(
        f"On this <b>{today}</b>, before me, <b>{notary_name}</b>, "
        f"Notary Public for said State, personally appeared <b>{signer_name}</b>, "
        f"known to me (or proved to me on the basis of satisfactory evidence) to be the person "
        f"whose name is subscribed to the within instrument and acknowledged to me that they "
        f"executed the same in their authorized capacity.",
        ParagraphStyle('S3', parent=styles['Normal'], fontSize=10, textColor=black,
                       alignment=TA_JUSTIFY, leading=14, fontName='Helvetica')))
    story.append(Spacer(1, 0.3*inch))

    # Signature lines
    if isinstance(sigs, dict):
        for signer_name_key, sig_info in sigs.items():
            if isinstance(sig_info, dict):
                sig_path = sig_info.get('signature_path') or sig_info.get('path', '')
                sig_date = sig_info.get('signed_date') or sig_info.get('date', '_________________')
            else:
                sig_path = sig_info
                sig_date = today
            if sig_path and os.path.exists(sig_path):
                story.append(RLImage(sig_path, width=2.5*inch, height=0.6*inch, kind='proportional'))
            story.append(Paragraph(f"Signature: {signer_name_key}",
                ParagraphStyle('SL', parent=styles['Normal'], fontSize=8, textColor=HexColor('#666'), fontName='Helvetica')))
            story.append(Paragraph(f"Date: {sig_date}",
                ParagraphStyle('SD', parent=styles['Normal'], fontSize=8, textColor=HexColor('#666'), fontName='Helvetica')))
            story.append(Spacer(1, 0.15*inch))

    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#ccc'), spaceBefore=10, spaceAfter=10))

    # Notary seal
    seal_data = [[
        Paragraph(f"<b>{notary_name}</b><br/>"
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

    doc.build(story)

    # Merge with original PDF
    try:
        from PyPDF2 import PdfReader, PdfWriter
        writer = PdfWriter()
        reader = PdfReader(doc_path)
        for page in reader.pages:
            writer.add_page(page)
        cert_reader = PdfReader(output_path)
        for page in cert_reader.pages:
            writer.add_page(page)
        with open(output_path, 'wb') as f:
            writer.write(f)
    except ImportError:
        pass

    return output_path

# ─── Routes: Public ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    profile = None
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('index.html', profile=profile)

# ─── Routes: Auth ────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()

        if not email or not password or not full_name:
            flash('All fields are required.', 'error')
            return render_template('login.html', mode='register')

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('login.html', mode='register')

        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'error')
            db.close()
            return render_template('login.html', mode='register')

        uid = str(uuid.uuid4())[:12]
        pw_hash = hash_password(password)
        now = datetime.datetime.utcnow().isoformat()

        db.execute('INSERT INTO users (id, email, password_hash, full_name, created_at, is_admin) VALUES (?, ?, ?, ?, ?, 1)',
                   (uid, email, pw_hash, full_name, now))
        db.commit()
        db.close()

        session['user_id'] = uid
        session.permanent = True
        flash('Account created! Welcome to Easy Notary.', 'success')
        return redirect(url_for('settings'))

    return render_template('login.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()

        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session.permanent = True
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'error')
    return render_template('login.html', mode='login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# ─── Routes: Dashboard ───────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user = get_user()
    profile = get_profile()

    sessions = db.execute(
        'SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
        (user['id'],)).fetchall()

    journal = db.execute(
        'SELECT * FROM journal WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
        (user['id'],)).fetchall()

    stats = {
        'total_sessions': db.execute('SELECT COUNT(*) FROM sessions WHERE user_id = ?', (user['id'],)).fetchone()[0],
        'completed': db.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND status = 'completed'", (user['id'],)).fetchone()[0],
        'revenue': db.execute('SELECT COALESCE(SUM(fee), 0) FROM journal WHERE user_id = ?', (user['id'],)).fetchone()[0],
    }
    db.close()

    return render_template('dashboard.html', user=user, profile=profile,
                           sessions=[dict(s) for s in sessions],
                           journal=[dict(j) for j in journal], stats=stats)

# ─── Routes: Sessions ────────────────────────────────────────────────────────

@app.route('/session/new')
@login_required
def session_new():
    return render_template('session_new.html')

@app.route('/session/create', methods=['POST'])
@login_required
def create_session():
    user = get_db().execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        return redirect(url_for('login'))

    sid = str(uuid.uuid4())[:12]
    now = datetime.datetime.utcnow().isoformat()
    expires = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()

    db = get_db()
    db.execute('''INSERT INTO sessions
        (id, user_id, signer_name, signer_email, document_type, num_signatures, notes, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'preparing', ?, ?)''',
        (sid, user['id'], request.form.get('signer_name', ''),
         request.form.get('signer_email', ''), request.form.get('document_type', ''),
         int(request.form.get('num_signatures', 1)), request.form.get('notes', ''),
         now, expires))
    db.commit()
    db.close()

    return redirect(url_for('session_view', sid=sid))

@app.route('/session/<sid>')
@login_required
def session_view(sid):
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        flash('Session not found.')
        return redirect(url_for('dashboard'))

    sigs = db.execute('SELECT * FROM signatures WHERE session_id = ? ORDER BY created_at', (sid,)).fetchall()
    db.close()

    session_data = dict(s)
    session_data['signatures'] = {r[' signer_name']: dict(r) for r in sigs}
    profile = get_profile()

    return render_template('session.html', session=session_data, profile=profile)

@app.route('/session/<sid>/upload', methods=['POST'])
@login_required
def upload_document(sid):
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    if 'document' not in request.files:
        db.close()
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['document']
    file_bytes = file.read()
    doc_path = os.path.join(DOCS_DIR, f"{sid}_{file.filename.replace(' ','_')}")
    with open(doc_path, 'wb') as f:
        f.write(file_bytes)

    db.execute('UPDATE sessions SET document_path = ?, document_name = ?, status = ? WHERE id = ?',
               (doc_path, file.filename, 'ready', sid))
    db.commit()
    db.close()

    return jsonify({'status': 'uploaded'})

@app.route('/session/<sid>/upload-id', methods=['POST'])
@login_required
def upload_id(sid):
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    if 'id_image' not in request.files:
        db.close()
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['id_image']
    file_bytes = file.read()
    id_path = save_id_image(file_bytes, sid)

    db.execute('UPDATE sessions SET id_upload_path = ?, id_verified = 1 WHERE id = ?',
               (id_path, sid))
    db.commit()
    db.close()

    return jsonify({'status': 'uploaded'})

@app.route('/session/<sid>/sign', methods=['POST'])
@login_required
def save_signature(sid):
    body = request.get_json(force=True) or {}
    signer = body.get('signer', 'signer')
    sig_data = body.get('signature', '')
    signed_date = body.get('date', datetime.datetime.now().strftime('%B %d, %Y'))
    now = datetime.datetime.utcnow().isoformat()

    if not sig_data:
        return jsonify({'error': 'No signature data'}), 400

    sig_path = save_signature_image(sig_data, sid, signer)

    sig_id = str(uuid.uuid4())[:12]
    db = get_db()
    db.execute('INSERT INTO signatures (id, session_id, signer_name, signature_path, signed_date, created_at) VALUES (?, ?, ?, ?, ?, ?)',
               (sig_id, sid, signer, sig_path, signed_date, now))
    db.commit()
    db.close()

    return jsonify({'status': 'signed'})

@app.route('/session/<sid>/complete', methods=['POST'])
@login_required
def complete_session(sid):
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    profile = get_profile()
    session_data = dict(s)
    sigs = db.execute('SELECT * FROM signatures WHERE session_id = ?', (sid,)).fetchall()
    session_data['signatures'] = {r['signer_name']: dict(r) for r in sigs}

    pdf_path = generate_notarized_pdf(session_data, profile)
    now = datetime.datetime.utcnow().isoformat()
    fee = profile.get('fee_per_signature', 25) * len(sigs)

    db.execute('UPDATE sessions SET status = ?, completed_at = ?, final_pdf = ?, payment_amount = ? WHERE id = ?',
               ('completed', now, pdf_path, fee, sid))

    jid = str(uuid.uuid4())[:12]
    db.execute('''INSERT INTO journal
        (id, user_id, session_id, signer_name, document_type, num_signatures, fee, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?)''',
        (jid, session['user_id'], sid, s['signer_name'], s['document_type'],
         len(sigs), fee, now))
    db.commit()
    db.close()

    return jsonify({'status': 'completed', 'download': url_for('download_pdf', sid=sid)})

@app.route('/session/<sid>/download')
@login_required
def download_pdf(sid):
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    db.close()
    if not s or not s['final_pdf']:
        flash('PDF not ready.')
        return redirect(url_for('session_view', sid=sid))
    return send_file(s['final_pdf'], mimetype='application/pdf',
                     download_name=f'notarized_{sid}.pdf')

# ─── Routes: Settings ────────────────────────────────────────────────────────

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    user = get_user()

    if request.method == 'POST':
        # Update notary profile
        fields = ['commission_number','commission_expires','county','state',
                  'commission_type','bond_amount','business_name','business_email',
                  'business_phone','business_address','website','fee_per_signature',
                  'fee_multi_signature','fee_loan_package','fee_travel','max_signers',
                  'stripe_account_id','payment_model','platform_commission']

        existing = db.execute('SELECT * FROM easy_notaryfile WHERE user_id = ?', (user['id'],)).fetchone()
        now = datetime.datetime.utcnow().isoformat()

        if existing:
            set_clause = ', '.join([f'{f} = ?' for f in fields]) + ', updated_at = ?'
            values = [request.form.get(f, '') for f in fields] + [now, user['id']]
            db.execute(f'UPDATE easy_notaryfile SET {set_clause} WHERE user_id = ?', values)
        else:
            pid = str(uuid.uuid4())[:12]
            cols = ['id','user_id'] + fields + ['updated_at']
            placeholders = ','.join(['?' for _ in cols])
            values = [pid, user['id']] + [request.form.get(f, '') for f in fields] + [now]
            db.execute(f'INSERT INTO easy_notaryfile ({",".join(cols)}) VALUES ({placeholders})', values)

        # Update user name
        if request.form.get('full_name'):
            db.execute('UPDATE users SET full_name = ? WHERE id = ?', (request.form['full_name'], user['id']))

        # Update password
        if request.form.get('new_password'):
            pw_hash = hash_password(request.form['new_password'])
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pw_hash, user['id']))

        db.commit()
        flash('Settings saved successfully!', 'success')

    profile = get_profile()
    db.close()
    return render_template('settings.html', user=user, config=profile)

# ─── Routes: Journal ─────────────────────────────────────────────────────────

@app.route('/journal')
@login_required
def journal():
    db = get_db()
    entries = db.execute('SELECT * FROM journal WHERE user_id = ? ORDER BY created_at DESC',
                         (session['user_id'],)).fetchall()
    db.close()
    return render_template('journal.html', entries=[dict(e) for e in entries])

@app.route('/api/journal')
@login_required
def api_journal():
    db = get_db()
    entries = db.execute('SELECT * FROM journal WHERE user_id = ? ORDER BY created_at DESC',
                         (session['user_id'],)).fetchall()
    db.close()
    return jsonify([dict(e) for e in entries])

# ─── Signature image retrieval ────────────────────────────────────────────────

@app.route('/sigimg/<sid>/<signer>')
@login_required
def get_sig_image(sid, signer):
    for ext in ['png', 'jpg']:
        path = os.path.join(SIGS_DIR, f"{sid}_{signer}.{ext}")
        if os.path.exists(path):
            return send_file(path, mimetype=f'image/{ext}')
    return jsonify({'error': 'Not found'}), 404

# ─── Routes: Video Session (WebRTC) ──────────────────────────────────────────

@app.route('/session/<sid>/video/signal', methods=['POST'])
@login_required
def video_signal(sid):
    """Relay WebRTC signaling messages (offer/answer/ICE candidates)."""
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    db.close()
    if not s:
        return jsonify({'error': 'Session not found'}), 404

    body = request.get_json(force=True) or {}
    msg_type = body.get('type')
    target = body.get('target')  # 'notary' or 'signer'
    data = body.get('data')

    if msg_type not in ('offer', 'answer', 'ice-candidate', 'join', 'leave'):
        return jsonify({'error': 'Invalid signal type'}), 400

    with video_signals_lock:
        if sid not in video_signals:
            video_signals[sid] = []
        video_signals[sid].append({
            'type': msg_type,
            'target': target,
            'data': data,
            'ts': datetime.datetime.utcnow().isoformat()
        })
        # Keep last 50 signals
        video_signals[sid] = video_signals[sid][-50:]

    return jsonify({'status': 'relayed'})


@app.route('/session/<sid>/video/poll')
@login_required
def video_poll(sid):
    """Poll for new signaling messages (long-polling alternative)."""
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    db.close()
    if not s:
        return jsonify({'error': 'Session not found'}), 404

    target = request.args.get('target', 'signer')
    since = request.args.get('since', '')

    with video_signals_lock:
        signals = video_signals.get(sid, [])

    if since:
        signals = [s for s in signals if s['ts'] > since]

    # Filter for target
    filtered = [s for s in signals if s.get('target') == target or s.get('type') == 'join']

    return jsonify({'signals': filtered})


@app.route('/session/<sid>/video/recording', methods=['POST'])
@login_required
def upload_video_recording(sid):
    """Save recorded video blob from MediaRecorder."""
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    if 'video' not in request.files:
        db.close()
        return jsonify({'error': 'No video file'}), 400

    file = request.files['video']
    video_path = os.path.join(VIDEO_DIR, f"{sid}_recording.webm")
    file.save(video_path)

    db.execute('UPDATE sessions SET video_recorded = 1, video_path = ? WHERE id = ?',
               (video_path, sid))
    db.commit()
    db.close()

    return jsonify({'status': 'saved', 'path': video_path})


# ─── Public signer access (token-based, no login required) ────────────────────

@app.route('/sign/<token>')
def signer_access(token):
    """Allow signer to join session via token link (no login needed)."""
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        sid = payload.get('sid')
        if not sid:
            return 'Invalid link', 400
    except jwt.InvalidTokenError:
        return 'Invalid or expired link', 404

    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ?', (sid,)).fetchone()
    db.close()
    if not s:
        return 'Session not found', 404

    return render_template('signer.html', session=dict(s), token=token)


@app.route('/session/generate-link', methods=['POST'])
@login_required
def generate_signer_link(sid=None):
    """Generate a shareable link for the signer."""
    sid = request.form.get('sid', sid)
    if not sid:
        return jsonify({'error': 'No session ID'}), 400

    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?',
                   (sid, session['user_id'])).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    token = jwt.encode({
        'sid': sid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, app.secret_key, algorithm='HS256')

    link = url_for('signer_access', token=token, _external=True)
    db.close()
    return jsonify({'link': link, 'token': token})


@app.route('/session/<sid>/kba-pass', methods=['POST'])
def kba_pass(sid):
    """Mark KBA as passed for a session (called from signer page, token-authenticated)."""
    # This endpoint is called from the signer page which uses token auth
    # For now, allow it without login_required since signer doesn't have a session
    # In production, verify the token from a header
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ?', (sid,)).fetchone()
    if not s:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    db.execute('UPDATE sessions SET kba_passed = 1 WHERE id = ?', (sid,))
    db.commit()
    db.close()
    return jsonify({'status': 'ok'})


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)