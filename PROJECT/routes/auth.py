from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database.db_connection import create_connection
from cryptography.fernet import Fernet
import base64
import mysql.connector
import re
from io import BytesIO
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import validators
import email
from email.header import decode_header
import dns.resolver
import json
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

class AppUser:
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)

# Common phishing indicators
PHISHING_INDICATORS = [
    r'login\.php\?',
    r'secure-verify\.',
    r'account-verification',
    r'password-update',
    r'login-form',
    r'user-auth',
    r'session-expired',
    r'verify-account',
    r'security-alert',
    r'urgent-action-required'
]

# Email phishing indicators
EMAIL_PHISHING_INDICATORS = [
    'urgent action required',
    'verify your account',
    'suspicious login attempt',
    'password expiration',
    'account suspension',
    'click here to verify',
    'security alert',
    'immediate action needed'
]

def is_suspicious_url(url):
    """Check if URL contains common phishing patterns"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    
    if any(x in domain for x in ['login-verify', 'account-secure', 'security-update']):
        return True
    
    if any(re.search(pattern, path) for pattern in PHISHING_INDICATORS):
        return True
    
    return False

def analyze_email_headers(headers):
    """Analyze email headers for signs of phishing or spoofing"""
    results = []
    
    if 'Received' not in headers:
        results.append("⚠️ Warning: No 'Received' headers found - possible spoofing attempt")
    
    auth_results = headers.get('Authentication-Results', '')
    if 'spf=pass' not in auth_results.lower():
        results.append("❌ SPF check failed - email may be spoofed")
    if 'dkim=pass' not in auth_results.lower():
        results.append("❌ DKIM check failed - email may be spoofed")
    if 'dmarc=pass' not in auth_results.lower():
        results.append("❌ DMARC check failed - email may be spoofed")
    
    from_header = headers.get('From', '')
    return_path = headers.get('Return-Path', '')
    if return_path and from_header and return_path not in from_header:
        results.append(f"⚠️ From/Return-Path mismatch: From={from_header}, Return-Path={return_path}")
    
    return results

def analyze_email_content(content):
    """Analyze email content for phishing indicators"""
    results = []
    content_lower = content.lower()
    
    for indicator in EMAIL_PHISHING_INDICATORS:
        if indicator in content_lower:
            results.append(f"⚠️ Phishing keyword found: '{indicator}'")
    
    soup = BeautifulSoup(content, 'html.parser')
    for link in soup.find_all('a', href=True):
        href = link['href']
        if is_suspicious_url(href):
            results.append(f"🔗 Suspicious link found: {href}")
    
    hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x.lower())
    if hidden_elements:
        results.append(f"👁️ Found {len(hidden_elements)} hidden elements - common in phishing emails")
    
    return results

def track_user_activity(user_id, activity_type, activity_data=None):
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()
        
        # Record the activity
        cursor.execute("""
            INSERT INTO user_activity (user_id, activity_type, activity_data)
            VALUES (%s, %s, %s)
        """, (user_id, activity_type, json.dumps(activity_data) if activity_data else None))
        
        # Update metrics
        today = datetime.now().date()
        cursor.execute("""
            INSERT INTO user_security_metrics (user_id, last_updated)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                scans_today = CASE WHEN last_updated = %s THEN scans_today ELSE 0 END,
                last_updated = %s
        """, (user_id, today, today, today))
        
        # Increment appropriate counters
        if activity_type == 'url_scan':
            cursor.execute("""
                UPDATE user_security_metrics 
                SET scans_today = scans_today + 1
                WHERE user_id = %s
            """, (user_id,))
        elif activity_type in ['email_scan', 'login_check']:
            if activity_data and activity_data.get('is_threat', False):
                cursor.execute("""
                    UPDATE user_security_metrics 
                    SET threats_blocked = threats_blocked + 1
                    WHERE user_id = %s
                """, (user_id,))
        
        conn.commit()
    except Exception as e:
        print(f"Error tracking activity: {e}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def calculate_security_score(user_id):
    """Calculate comprehensive security score based on user activity"""
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user metrics
        cursor.execute("""
            SELECT scans_today, threats_blocked 
            FROM user_security_metrics
            WHERE user_id = %s
        """, (user_id,))
        metrics = cursor.fetchone() or {'scans_today': 0, 'threats_blocked': 0}
        
        # Get activity counts
        cursor.execute("""
            SELECT activity_type, COUNT(*) as count
            FROM user_activity
            WHERE user_id = %s
            GROUP BY activity_type
        """, (user_id,))
        activities = {row['activity_type']: row['count'] for row in cursor.fetchall()}
        
        # Calculate score (simplified example - adjust weights as needed)
        score = 50  # Base score
        
        # Positive factors
        score += min(activities.get('url_scan', 0) * 2, 20)
        score += min(activities.get('email_scan', 0) * 3, 15)
        score += min(activities.get('quiz', 0) * 5, 25)
        
        # Negative factors
        score -= min(metrics['threats_blocked'], 10) * 2
        
        # Cap between 0-100
        score = max(0, min(100, score))
        
        return score
        
    except Exception as e:
        print(f"Error calculating security score: {e}")
        return 75  # Default score if calculation fails
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    # Get user metrics
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT scans_today, threats_blocked
            FROM user_security_metrics
            WHERE user_id = %s
        """, (current_user.id,))
        metrics = cursor.fetchone() or {'scans_today': 0, 'threats_blocked': 0}
        
        security_score = calculate_security_score(current_user.id)
        
        return render_template('dashboard.html', 
                            username=current_user.username,
                            security_score=security_score,
                            scans_today=metrics['scans_today'],
                            threats_blocked=metrics['threats_blocked'])
    
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        return render_template('dashboard.html',
                             username=current_user.username,
                             security_score=75,
                             scans_today=0,
                             threats_blocked=0)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@auth_bp.route('/email-analyzer', methods=['GET', 'POST'])
@login_required
def email_analyzer():
    if request.method == 'POST':
        email_content = request.form.get('email_content')
        if not email_content:
            flash("Email content is required", "danger")
            return redirect(url_for('auth.dashboard'))
        
        try:
            try:
                msg = email.message_from_string(email_content)
                headers = dict(msg.items())
                body = ""
                
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == 'text/plain' or content_type == 'text/html':
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                else:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                headers = {}
                body = email_content
            
            analysis_results = []
            
            if headers:
                header_results = analyze_email_headers(headers)
                analysis_results.extend(header_results)
            
            if body:
                content_results = analyze_email_content(body)
                analysis_results.extend(content_results)
            
            if not analysis_results:
                analysis_results.append("✅ No obvious phishing indicators found")
            
            # Track this activity
            is_threat = any('⚠️' in item or '❌' in item for item in analysis_results)
            track_user_activity(current_user.id, 'email_scan', {
                'is_threat': is_threat,
                'threat_count': sum(1 for item in analysis_results if '⚠️' in item or '❌' in item)
            })
            
            return render_template('dashboard.html', 
                                username=current_user.username,
                                analysis=analysis_results,
                                active_section='email-analyzer')
        
        except Exception as e:
            flash(f"Error analyzing email: {str(e)}", "danger")
    
    return render_template('dashboard.html',
                         username=current_user.username,
                         active_section='email-analyzer')

def analyze_login_page(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        phishing_signs = []
        
        password_fields = soup.find_all('input', {'type': 'password'})
        if not password_fields:
            phishing_signs.append("No password input field found - unusual for a login page")
        
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            if action and is_suspicious_url(action):
                phishing_signs.append(f"Suspicious form action: {action}")
        
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href'].lower()
            if is_suspicious_url(href):
                phishing_signs.append(f"Suspicious link found: {href}")
        
        phishing_keywords = ['verify', 'secure', 'update', 'confirm', 'validate']
        text = soup.get_text().lower()
        if any(keyword in text for keyword in phishing_keywords):
            phishing_signs.append("Page contains common phishing keywords")
        
        return {
            'is_phishing': len(phishing_signs) > 2,
            'phishing_signs': phishing_signs,
            'status_code': response.status_code,
            'final_url': response.url
        }
        
    except requests.exceptions.RequestException as e:
        return {
            'error': str(e),
            'is_phishing': True
        }

def scan_url(url):
    if not validators.url(url):
        return {'error': 'Invalid URL format'}
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        suspicious = is_suspicious_url(url)
        is_login_page = False
        login_page_analysis = {}
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10, verify=True)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                is_login_page = True
                login_page_analysis = analyze_login_page(url)
            
            malicious_patterns = [
                'iframe', 'hidden', 'eval(', 'document.write',
                'window.location', 'document.cookie'
            ]
            
            scripts = soup.find_all('script')
            malicious_scripts = []
            for script in scripts:
                if script.string:
                    for pattern in malicious_patterns:
                        if pattern in script.string.lower():
                            malicious_scripts.append(pattern)
                            break
            
            return {
                'url': url,
                'domain': domain,
                'is_suspicious': suspicious,
                'is_login_page': is_login_page,
                'login_page_analysis': login_page_analysis if is_login_page else None,
                'malicious_scripts_found': malicious_scripts if malicious_scripts else None,
                'status_code': response.status_code,
                'final_url': response.url,
                'error': None
            }
            
        except requests.exceptions.SSLError:
            return {
                'url': url,
                'domain': domain,
                'is_suspicious': True,
                'ssl_error': True,
                'warning': 'SSL certificate verification failed - potential security risk'
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'domain': domain,
                'is_suspicious': True,
                'error': str(e)
            }
            
    except Exception as e:
        return {
            'error': f'Scanning error: {str(e)}'
        }

@auth_bp.route('/scan-url', methods=['POST'])
@login_required
def handle_url_scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    scan_result = scan_url(url)
    
    # Track this activity
    track_user_activity(current_user.id, 'url_scan', {
        'url': url,
        'is_threat': scan_result.get('is_suspicious', False)
    })
    
    return jsonify(scan_result)

@auth_bp.route('/check-login-page', methods=['POST'])
@login_required
def check_login_page():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    result = analyze_login_page(url)
    return jsonify(result)

@auth_bp.route('/api/user-metrics')
@login_required
def get_user_metrics():
    try:
        security_score = calculate_security_score(current_user.id)
        
        conn = create_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT scans_today, threats_blocked
            FROM user_security_metrics
            WHERE user_id = %s
        """, (current_user.id,))
        metrics = cursor.fetchone() or {'scans_today': 0, 'threats_blocked': 0}
        
        return jsonify({
            'security_score': security_score,
            'scans_today': metrics['scans_today'],
            'threats_blocked': metrics['threats_blocked']
        })
    except Exception as e:
        return jsonify({
            'security_score': 75,
            'scans_today': 0,
            'threats_blocked': 0
        })

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = None
        cursor = None
        try:
            conn = create_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()

            if user_data and check_password_hash(user_data['password'], password):
                user = AppUser(user_data['id'], user_data['username'], user_data['email'])
                login_user(user)
                flash("Logged in successfully!", "success")
                return redirect(url_for('auth.dashboard'))
            else:
                flash("Invalid email or password", "danger")

        except mysql.connector.Error as err:
            flash(f"Database error occurred: {err}", "danger")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        security_question = request.form['security_question'].strip()
        security_answer = request.form['security_answer'].strip().lower()

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return render_template('register.html')

        conn = None
        cursor = None
        try:
            conn = create_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already registered", "danger")
                return render_template('register.html')
            
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash("Username already taken", "danger")
                return render_template('register.html')

            hashed_password = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, email, password, security_question, security_answer)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, hashed_password, security_question, security_answer))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('auth.login'))

        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Database error occurred: {err}", "danger")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('register.html')

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.args.get('reset'):
        session.pop('reset_stage', None)
        session.pop('reset_username', None)
        return redirect(url_for('auth.reset_password'))

    stage = session.get('reset_stage', 1)

    if request.method == 'POST':
        conn = None
        cursor = None
        try:
            conn = create_connection()
            cursor = conn.cursor(dictionary=True)

            if stage == 1:
                username = request.form.get('username').strip()
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                
                if user:
                    session['reset_username'] = username
                    session['reset_stage'] = 2
                    return render_template('reset_password.html', 
                                        stage=2, 
                                        question=user['security_question'])
                else:
                    flash("Username not found.", "error")

            elif stage == 2:
                answer = request.form.get('security_answer').strip().lower()
                username = session.get('reset_username')
                cursor.execute("""
                    SELECT security_answer FROM users 
                    WHERE username = %s
                """, (username,))
                user = cursor.fetchone()
                
                if user and user['security_answer'].lower() == answer:
                    session['reset_stage'] = 3
                    return render_template('reset_password.html', stage=3)
                else:
                    flash("Incorrect answer to the security question.", "error")

            elif stage == 3:
                password = request.form.get('password')
                confirm = request.form.get('confirm_password')
                username = session.get('reset_username')
                
                if password != confirm:
                    flash("Passwords do not match.", "error")
                elif len(password) < 6:
                    flash("Password must be at least 6 characters.", "error")
                else:
                    hashed_pw = generate_password_hash(password)
                    cursor.execute("""
                        UPDATE users SET password = %s 
                        WHERE username = %s
                    """, (hashed_pw, username))
                    conn.commit()
                    flash("Password reset successful! Please login with your new password.", "success")
                    
                    session.pop('reset_username', None)
                    session.pop('reset_stage', None)
                    return redirect(url_for('auth.login'))

        except mysql.connector.Error as err:
            flash(f"Database error occurred: {err}", "error")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('reset_password.html', stage=stage)

@auth_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()

    if not username or not email:
        flash("Both username and email are required", "danger")
        return redirect(url_for('auth.dashboard'))

    try:
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET username = %s, email = %s WHERE id = %s", (username, email, current_user.id))
        conn.commit()
        flash("Profile updated successfully", "success")
    except Exception as e:
        flash(f"Error updating profile: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/update-security-question', methods=['POST'])
@login_required
def update_security_question():
    question = request.form.get('security_question')
    answer = request.form.get('security_answer', '').strip()

    if not question or not answer:
        flash("Both security question and answer are required.", "danger")
        return redirect(url_for('auth.dashboard'))

    try:
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET security_question = %s, security_answer = %s
            WHERE id = %s
        """, (question, answer.lower(), current_user.id))
        conn.commit()
        flash("Security question updated successfully.", "success")
    except Exception as e:
        flash(f"Failed to update security question: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/encrypt-tool', methods=['GET', 'POST'])
@login_required
def encrypt_tool():
    if request.method == 'POST':
        encryption_key = request.form.get('encryption-key')
        text_input = request.form.get('text-input')
        file_input = request.files.get('file-input')
        
        if not encryption_key:
            flash("Encryption key is required", "danger")
            return render_template('dashboard.html', username=current_user.username)
            
        try:
            key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32].encode())
            cipher = Fernet(key)
            
            if text_input:
                encrypted_data = cipher.encrypt(text_input.encode())
                return render_template('dashboard.html', 
                                    username=current_user.username,
                                    encrypted_text=encrypted_data.decode())
                
            elif file_input:
                file_data = file_input.read()
                encrypted_data = cipher.encrypt(file_data)
                
                mem_file = BytesIO()
                mem_file.write(encrypted_data)
                mem_file.seek(0)
                
                original_filename = file_input.filename
                if '.' in original_filename:
                    ext = original_filename.rsplit('.', 1)[1].lower()
                    new_filename = f"encrypted_{original_filename.rsplit('.', 1)[0]}.enc.{ext}"
                else:
                    new_filename = f"encrypted_{original_filename}.enc"
                
                return send_file(
                    mem_file,
                    as_attachment=True,
                    download_name=new_filename,
                    mimetype='application/octet-stream'
                )
                
        except Exception as e:
            flash(f"Encryption failed: {str(e)}", "danger")
    
    return render_template('dashboard.html', username=current_user.username)

@auth_bp.route('/decrypt-tool', methods=['POST'])
@login_required
def decrypt_tool():
    if request.method == 'POST':
        encryption_key = request.form.get('encryption-key')
        text_input = request.form.get('text-input')
        file_input = request.files.get('file-input')
        
        if not encryption_key:
            flash("Encryption key is required", "danger")
            return render_template('dashboard.html', username=current_user.username)
            
        try:
            key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32].encode())
            cipher = Fernet(key)
            
            if text_input:
                decrypted_data = cipher.decrypt(text_input.encode())
                return render_template('dashboard.html', 
                                    username=current_user.username,
                                    decrypted_text=decrypted_data.decode())
                
            elif file_input:
                file_data = file_input.read()
                decrypted_data = cipher.decrypt(file_data)
                
                mem_file = BytesIO()
                mem_file.write(decrypted_data)
                mem_file.seek(0)
                
                original_filename = file_input.filename
                if original_filename.startswith('encrypted_') and '.enc.' in original_filename:
                    parts = original_filename.split('.enc.')
                    new_filename = parts[0][10:] + '.' + parts[1]
                else:
                    new_filename = 'decrypted_' + original_filename
                
                return send_file(
                    mem_file,
                    as_attachment=True,
                    download_name=new_filename,
                    mimetype='application/octet-stream'
                )
                
        except Exception as e:
            flash(f"Decryption failed: {str(e)}", "danger")
    
    return render_template('dashboard.html', username=current_user.username)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('auth.login'))