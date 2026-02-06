from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import cv2
import numpy as np
from pyzbar.pyzbar import decode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ma_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --- MODELES ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qr_content = db.Column(db.String(255), unique=True, nullable=False) # UNIQUE maintenant
    visits = db.Column(db.Integer, default=0) # Le compteur ++
    last_scanned_at = db.Column(db.DateTime, default=datetime.now) # Heure du DERNIER scan
    last_scanned_by = db.Column(db.String(100)) # Qui l'a scanné en dernier

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AUTH (Inchangé) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('scanner'))
        flash('Erreur identifiants')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- APP SCANNER ---

@app.route('/')
@login_required
def scanner():
    return render_template('scanner.html')

@app.route('/api/process_scan', methods=['POST'])
@login_required
def process_scan():
    data = request.json
    qr_code = data.get('qr_code')
    if not qr_code:
        return jsonify({'status': 'error', 'message': 'QR Vide'}), 400
    return save_scan(qr_code)

@app.route('/api/analyze_image', methods=['POST'])
@login_required
def analyze_image():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'Aucun fichier reçu'}), 400
    file = request.files['file']
    try:
        file_bytes = np.fromfile(file, np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        decoded_objects = decode(img)
        if not decoded_objects:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            decoded_objects = decode(gray)
        if not decoded_objects:
            return jsonify({'status': 'error', 'message': 'Aucun QR code détecté'}), 404

        qr_content = decoded_objects[0].data.decode("utf-8")
        return save_scan(qr_content)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- LOGIQUE DE SAUVEGARDE (LA CORRECTION EST ICI) ---

def save_scan(qr_content):
    """Cherche si le QR existe, sinon le crée, et fait ++"""
    scan = ScanLog.query.filter_by(qr_content=qr_content).first()
    
    if scan:
        # Si le QR existe déjà, on incrémente
        scan.visits += 1
        scan.last_scanned_at = datetime.now()
        scan.last_scanned_by = current_user.username
    else:
        # Si c'est un nouveau QR, on crée la ligne
        scan = ScanLog(
            qr_content=qr_content, 
            visits=1, 
            last_scanned_by=current_user.username
        )
        db.session.add(scan)
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'qr_code': qr_content,
        'count': scan.visits,
        'timestamp': scan.last_scanned_at.strftime("%H:%M:%S")
    })

# --- DASHBOARD & EXPORT ---

@app.route('/dashboard')
@login_required
def dashboard():
    # Affiche une ligne par QR unique, trié par le plus récemment scanné
    logs = ScanLog.query.order_by(ScanLog.last_scanned_at.desc()).all()
    return render_template('dashboard.html', logs=logs)

@app.route('/export_csv')
@login_required
def export_csv():
    logs = ScanLog.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Contenu QR', 'Nombre de Scans', 'Dernier Scan', 'Par'])
    for log in logs:
        writer.writerow([log.qr_content, log.visits, log.last_scanned_at, log.last_scanned_by])
    return Response(output.getvalue(), mimetype="text/csv", 
                    headers={"Content-disposition": "attachment; filename=stats_qr.csv"})

# --- INIT ---
def create_admin():
    if not User.query.filter_by(username='lalilalou').first():
        hashed = generate_password_hash('lalilalou2026', method='scrypt')
        db.session.add(User(username='lalilalou', password=hashed))
        db.session.commit()

with app.app_context():
    db.create_all()
    create_admin()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')