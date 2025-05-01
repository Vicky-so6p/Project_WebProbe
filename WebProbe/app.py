import os
import json
import requests
from flask import jsonify
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from virustotal import VirusTotalScanner
from datetime import datetime as dt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import random
from bs4 import BeautifulSoup
import hashlib

import sys
sys.path.append('../')
from gemini_test import analyze_url_purpose, analyze_scan_report

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abienterpriseabi@gmail.com'
app.config['MAIL_PASSWORD'] = 'zyrx hreq lecs lkuj'
app.config['MAIL_DEFAULT_SENDER'] = 'abienterpriseabi@gmail.com'

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

def datetime_filter(value):
    return dt.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

app.jinja_env.filters['datetime'] = datetime_filter

VT_API_KEY = os.getenv('VT_API_KEY', 'ENTER_YOUR_API_KRY')
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

# Models (move to models.py later)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    result = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# VirusTotal Scanner instance
vt_scanner = VirusTotalScanner('9645a73701f67896fb14607abadff114ed069d81dfef4c67a4a1da9af8737ff6')

# Routes
@app.route('/')
def index():
    return redirect(url_for('user_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('user_dashboard'))
        flash('Invalid credentials')
    return render_template('user_login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists')
        else:
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp
            session['signup_data'] = {'username': username, 'email': email, 'password': password}
            msg = Message('Your OTP for Signup', recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            return redirect(url_for('otp_verification'))
    return render_template('user_signup.html')

@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session.get('otp'):
            data = session.get('signup_data')
            user = User(username=data['username'], email=data['email'], password=data['password'])
            db.session.add(user)
            db.session.commit()
            session.pop('otp', None)
            session.pop('signup_data', None)
            flash('Signup successful! Please login.')
            return redirect(url_for('user_login'))
        flash('Invalid OTP')
    return render_template('otp_verification.html')

@app.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    url_purpose = None
    if request.method == 'POST':
        url = request.form['url']
        vt_result = vt_scanner.scan_url(url)
        if vt_result:
            stats = vt_result['data']['attributes']['stats']
            total_scans = sum(stats.values())
            malicious_count = stats['malicious'] + stats['suspicious']
            percentage = (malicious_count / total_scans * 100) if total_scans > 0 else 0

            if percentage >= 50:
                category = "Dangerous"
            elif percentage >= 20:
                category = "Moderate"
            elif percentage > 0:
                category = "Suspicious"
            else:
                category = "Safe"

            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                print(f"*** App - Attempting to fetch URL metadata: {url} ***")  # Debugging
                response = requests.get(url, timeout=10, headers=headers)
                response.raise_for_status()
                headers = {k.lower(): v for k, v in response.headers.items()}
                serving_ip = requests.get(f"http://ip-api.com/json/{url.split('//')[-1].split('/')[0]}").json().get('query', 'Unknown')
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else 'No Title'
                meta_tags = {meta.get('name', meta.get('property', 'unnamed')): meta.get('content')
                            for meta in soup.find_all('meta') if meta.get('content')}
                extra_info = {
                    "final_url": response.url,
                    "serving_ip": serving_ip,
                    "status_code": response.status_code,
                    "body_length": f"{len(response.content) / 1024:.2f} KB",
                    "body_sha256": hashlib.sha256(response.content).hexdigest(),
                    "headers": headers,
                    "html_info": {"title": title, "meta_tags": meta_tags},
                    "trackers": ["Google Tag Manager"] if "googletagmanager" in response.text.lower() else [],
                    "redirection_chain": [r.url for r in response.history] + [response.url] if response.history else [response.url]
                }

                # Analyze URL purpose
                print(f"*** App - Calling analyze_url_purpose for: {url} ***")  # Debugging
                url_purpose = analyze_url_purpose(url)
                print(f"*** App - URL Purpose received: {url_purpose} ***")  # Debugging

            except requests.RequestException as e:
                print(f"*** App - Error fetching URL metadata: {e} ***")  # Debugging
                flash(f"Error fetching URL metadata: {e}")
                extra_info = {}

        scan = ScanHistory(user_id=current_user.id, url=url, result=json.dumps(vt_result))
        db.session.add(scan)
        db.session.commit()
        return render_template('report.html', result=vt_result, url=url, percentage=percentage,
                             category=category, extra_info=extra_info, url_purpose=url_purpose, scan=scan)
    return render_template('user_dashboard.html')
        # --- Up to here ---

@app.route('/download_report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return "Unauthorized", 403
    
    result = json.loads(scan.result)
    stats = result['data']['attributes']['stats']
    total_scans = sum(stats.values())
    malicious_count = stats['malicious'] + stats['suspicious']
    percentage = (malicious_count / total_scans * 100) if total_scans > 0 else 0
    category = "Dangerous" if percentage >= 50 else "Moderate" if percentage >= 20 else "Suspicious" if percentage > 0 else "Safe"
    
    # Fetch metadata dynamically (replicating dashboard logic)
    try:
        response = requests.get(scan.url, timeout=10)
        response.raise_for_status()
        headers = {k.lower(): v for k, v in response.headers.items()}
        serving_ip = requests.get(f"http://ip-api.com/json/{scan.url.split('//')[-1].split('/')[0]}").json().get('query', 'Unknown')
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else 'No Title'
        meta_tags = {meta.get('name', meta.get('property', 'unnamed')): meta.get('content') 
                    for meta in soup.find_all('meta') if meta.get('content')}
        extra_info = {
            "final_url": response.url,
            "serving_ip": serving_ip,
            "status_code": response.status_code,
            "body_length": f"{len(response.content) / 1024:.2f} KB",
            "body_sha256": hashlib.sha256(response.content).hexdigest(),
            "headers": headers,
            "html_info": {"title": title, "meta_tags": meta_tags},
            "trackers": ["Google Tag Manager"] if "googletagmanager" in response.text.lower() else [],
            "redirection_chain": [r.url for r in response.history] + [response.url] if response.history else [response.url]
        }
    except requests.RequestException:
        extra_info = {}

    pdf_file = f"report_{scan_id}.pdf"
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"Scan Report for {scan.url}", styles['Title']))
    story.append(Spacer(1, 12))

    # Maliciousness Overview
    story.append(Paragraph("Maliciousness Overview", styles['Heading2']))
    story.append(Paragraph(f"Percentage: {percentage:.1f}%", styles['Normal']))
    story.append(Paragraph(f"Category: {category}", styles['Normal']))
    story.append(Spacer(1, 12))

    # VirusTotal Summary
    story.append(Paragraph("VirusTotal Summary", styles['Heading2']))
    summary_data = [
        ["Metric", "Count"],
        ["Malicious", str(stats['malicious'])],
        ["Suspicious", str(stats['suspicious'])],
        ["Harmless", str(stats['harmless'])],
        ["Undetected", str(stats['undetected'])]
    ]
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Detailed Results
    story.append(Paragraph("Detailed Scan Results", styles['Heading2']))
    detailed_data = [["Vendor", "Category", "Result"]]
    for vendor, details in result['data']['attributes']['results'].items():
        detailed_data.append([vendor, details['category'], details['result'] or 'N/A'])
    detailed_table = Table(detailed_data, colWidths=[200, 100, 150])
    detailed_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(detailed_table)
    story.append(Spacer(1, 12))

    # Metadata
    if extra_info:
        story.append(Paragraph("URL Metadata", styles['Heading2']))
        story.append(Paragraph(f"Final URL: {extra_info['final_url']}", styles['Normal']))
        story.append(Paragraph(f"Serving IP Address: {extra_info['serving_ip']}", styles['Normal']))
        story.append(Paragraph(f"Status Code: {extra_info['status_code']}", styles['Normal']))
        story.append(Paragraph(f"Body Length: {extra_info['body_length']}", styles['Normal']))
        story.append(Paragraph(f"Body SHA-256: {extra_info['body_sha256']}", styles['Normal']))
        
        story.append(Paragraph("Headers:", styles['Normal']))
        for key, value in extra_info['headers'].items():
            story.append(Paragraph(f"{key}: {value}", styles['Normal']))
        
        story.append(Paragraph("HTML Info:", styles['Normal']))
        story.append(Paragraph(f"Title: {extra_info['html_info']['title']}", styles['Normal']))
        story.append(Paragraph("Meta Tags:", styles['Normal']))
        for key, value in extra_info['html_info']['meta_tags'].items():
            story.append(Paragraph(f"{key}: {value}", styles['Normal']))
        
        story.append(Paragraph(f"Trackers: {', '.join(extra_info['trackers']) or 'None detected'}", styles['Normal']))
        story.append(Paragraph(f"Redirection Chain: {' -> '.join(extra_info['redirection_chain'])}", styles['Normal']))
    else:
        story.append(Paragraph("URL Metadata: Not available", styles['Normal']))
    story.append(Spacer(1, 12))

    # Scan Info
    story.append(Paragraph("Scan Information", styles['Heading2']))
    story.append(Paragraph(f"Analysis ID: {result['data']['id']}", styles['Normal']))
    story.append(Paragraph(f"Date: {datetime_filter(result['data']['attributes']['date'])}", styles['Normal']))
    story.append(Paragraph(f"Status: {result['data']['attributes']['status']}", styles['Normal']))

    doc.build(story)
    return send_file(pdf_file, as_attachment=True)

#chatbot route
@app.route('/ask_report_bot/<int:scan_id>', methods=['POST'])
@login_required
def ask_report_bot(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    user_query = data.get('query')

    if not user_query:
        return jsonify({'error': 'No query provided'}), 400

    scan_result = json.loads(scan.result)

    gemini_response = analyze_scan_report(scan_result, user_query)

    return jsonify({'response': gemini_response})
#route end

@app.route('/history')
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('admin_logged_in', None)
    return redirect(url_for('user_login'))

if __name__ == '__main__':
    instance_path = os.path.join(os.path.dirname(__file__), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)