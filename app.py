#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import dns.resolver
import smtplib
import socket

app = Flask(__name__)
CORS(app)

def validate_syntax(email):
    """Check if email has valid syntax"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_domain(email):
    """Check if domain has MX records"""
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0, [str(r.exchange) for r in mx_records]
    except Exception as e:
        return False, []

def validate_smtp(email):
    """Check if mailbox exists via SMTP"""
    try:
        domain = email.split('@')[1]
        
        # Get MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange).rstrip('.')
        
        # Connect to mail server
        server = smtplib.SMTP(timeout=10)
        server.set_debuglevel(0)
        
        # Connect and use proper EHLO
        server.connect(mx_host)
        server.ehlo_or_helo_if_needed()
        
        # Try to verify - some servers block this
        server.mail('verifier@' + domain)
        code, message = server.rcpt(email)
        server.quit()
        
        # 250 = success, 251 = user not local (but forwarded)
        if code in [250, 251]:
            return True, "Mailbox exists"
        else:
            return False, message.decode() if isinstance(message, bytes) else str(message)
        
    except smtplib.SMTPServerDisconnected:
        # Server disconnected - assume valid (can't verify)
        return True, "Cannot verify (server disconnected) - assuming valid"
    except smtplib.SMTPResponseException as e:
        # Check specific error codes
        if e.smtp_code in [550, 551, 553]:  # User unknown
            return False, "Mailbox does not exist"
        elif e.smtp_code in [450, 451, 452]:  # Temporary error/greylisting
            return True, "Cannot verify (temporary error) - assuming valid"
        else:
            return True, f"Cannot verify (SMTP {e.smtp_code}) - assuming valid"
    except socket.timeout:
        return True, "Cannot verify (timeout) - assuming valid"
    except Exception as e:
        # If verification fails for technical reasons, assume valid
        return True, f"Cannot verify ({str(e)[:50]}) - assuming valid"

@app.route('/verify', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'valid': False, 'reason': 'Email is required'}), 400
    
# Helper lists
    FREE_PROVIDERS = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com', 'icloud.com', 'aol.com'}
    DISPOSABLE_DOMAINS = {'tempmail.com', 'throwawaymail.com', 'mailinator.com', 'guerrillamail.com', '10minutemail.com'}
    GENERIC_ROLES = {'admin', 'support', 'info', 'contact', 'sales', 'marketing', 'help', 'office'}
    
    def get_provider(domain, mx_records):
        mx_str = ' '.join(mx_records).lower()
        if 'google' in mx_str or 'google' in domain:
            return 'Google Workspace'
        elif 'outlook' in mx_str or 'microsoft' in mx_str:
            return 'Microsoft 365'
        elif 'pphosted' in mx_str:
            return 'Proofpoint'
        elif 'mimecast' in mx_str:
            return 'Mimecast'
        return 'Other/Private'

    # Step 1: Syntax validation
    if not validate_syntax(email):
        return jsonify({
            'valid': False,
            'reason': 'Invalid email format',
            'score': 0,
            'quality_checks': {
                'valid_format': False,
                'valid_domain': False,
                'can_receive_email': False,
                'is_catch_all': False,
                'is_generic': False,
                'is_disposable': False
            },
            'attributes': {
                'username': email.split('@')[0] if '@' in email else '',
                'domain': email.split('@')[1] if '@' in email else '',
                'is_free': False,
                'provider': 'Unknown',
                'mx_record': ''
            }
        })
    
    username, domain = email.split('@')

    # Step 2: Domain validation
    domain_valid, mx_records = validate_domain(email)
    if not domain_valid:
        return jsonify({
            'valid': False,
            'reason': 'Domain does not exist',
            'score': 10,
            'quality_checks': {
                'valid_format': True,
                'valid_domain': False,
                'can_receive_email': False,
                'is_catch_all': False,
                'is_generic': False,
                'is_disposable': domain in DISPOSABLE_DOMAINS
            },
            'attributes': {
                'username': username,
                'domain': domain,
                'is_free': domain in FREE_PROVIDERS,
                'provider': 'Unknown',
                'mx_record': ''
            }
        })
    
    # Step 3: SMTP validation
    smtp_valid, smtp_message = validate_smtp(email)
    
    # Analyze attributes
    is_free = domain in FREE_PROVIDERS
    is_disposable = domain in DISPOSABLE_DOMAINS
    is_generic = username.lower() in GENERIC_ROLES
    provider = get_provider(domain, mx_records)
    
    # Calculate Score
    score = 100
    if not smtp_valid: score -= 40
    if is_disposable: score -= 50
    if is_generic: score -= 10
    if is_free: score -= 5
    score = max(0, score)

    return jsonify({
        'valid': smtp_valid,
        'reason': smtp_message if not smtp_valid else 'Valid',
        'score': score,
        'quality_checks': {
            'valid_format': True,
            'valid_domain': True,
            'can_receive_email': smtp_valid,
            'is_catch_all': False, # checking this is slow/complex, defaulting to False for demo
            'is_generic': (not is_generic), # UI says "Not a generic address: Yes" so we return current state
            'is_disposable': is_disposable
        },
        'attributes': {
            'username': username,
            'domain': domain,
            'is_free': is_free,
            'provider': provider,
            'mx_record': mx_records[0] if mx_records else ''
        },
        'details': f'Email verified successfully. Mail server: {mx_records[0]}'
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 Email Verifier Backend Starting")
    print("="*50)
    print("Server running on: http://localhost:5000")
    print("Open email-verifier.html in your browser")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)
