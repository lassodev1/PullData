from flask import Flask, request, jsonify
from flask_cors import CORS
from simple_salesforce import Salesforce, SalesforceError
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlencode
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models import (
    get_db_session, ApiKey, Organization, User, ChatSession, Message,
    PasswordResetToken, decrypt, hash_password, check_password
)
import bcrypt
import jwt
import anthropic
import requests
import smtplib
import secrets
import json
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

ALLOWED_ORIGIN    = os.getenv('ALLOWED_ORIGIN', 'https://asklasso.com')
FRONTEND_URL      = os.getenv('FRONTEND_URL',   'https://asklasso.com')
DAILY_QUERY_LIMIT = int(os.getenv('DAILY_QUERY_LIMIT', '100'))

# In-memory store for pending OAuth state nonces {nonce: {org_id, expires_at}}
# Single-instance safe; for multi-instance use Redis instead.
_oauth_states: dict = {}

# --- CORS ---

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin']  = ALLOWED_ORIGIN
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin']  = ALLOWED_ORIGIN
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response

# --- Auth helpers ---

def generate_token(user_id, org_id):
    payload = {
        'user_id': user_id,
        'org_id':  org_id,
        'exp':     datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

def decode_token(token):
    return jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])

def get_org_from_request():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, None

    token = auth_header.split('Bearer ')[1].strip()

    try:
        payload = decode_token(token)
        db      = get_db_session()
        org     = db.query(Organization).filter_by(id=payload['org_id']).first()
        user_id = payload['user_id']
        db.close()
        return org, user_id
    except jwt.InvalidTokenError:
        pass

    db = get_db_session()
    api_keys = db.query(ApiKey).filter_by(active=True).all()
    org = None
    for key in api_keys:
        if bcrypt.checkpw(token.encode(), key.key_hash.encode()):
            org = db.query(Organization).filter_by(id=key.org_id).first()
            break
    db.close()
    return org, None

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing API key'}), 401

        token = auth_header.split('Bearer ')[1].strip()

        try:
            decode_token(token)
            return f(*args, **kwargs)
        except jwt.InvalidTokenError:
            pass

        db = get_db_session()
        api_keys = db.query(ApiKey).filter_by(active=True).all()
        valid = False
        for key in api_keys:
            if bcrypt.checkpw(token.encode(), key.key_hash.encode()):
                valid = True
                break
        db.close()

        if not valid:
            return jsonify({'error': 'Invalid API key'}), 401

        return f(*args, **kwargs)
    return decorated

# --- Rate limiting ---

def check_rate_limit(user_id):
    if not user_id:
        return True, 0, DAILY_QUERY_LIMIT

    db          = get_db_session()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    used = (
        db.query(Message)
        .join(ChatSession, Message.session_id == ChatSession.id)
        .filter(
            ChatSession.user_id == user_id,
            Message.role        == 'user',
            Message.created_at  >= today_start
        )
        .count()
    )
    db.close()
    return used < DAILY_QUERY_LIMIT, used, DAILY_QUERY_LIMIT

# --- Email helper ---

def send_email(to_address: str, subject: str, html_body: str):
    """Send an HTML email via SMTP (Gmail app password or any SMTP provider)."""
    msg            = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = os.getenv('EMAIL_FROM', 'askLasso <no-reply@asklasso.com>')
    msg['To']      = to_address
    msg.attach(MIMEText(html_body, 'html'))

    with smtplib.SMTP(os.getenv('SMTP_HOST', 'smtp.gmail.com'),
                      int(os.getenv('SMTP_PORT', 587))) as s:
        s.starttls()
        s.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASS'))
        s.sendmail(msg['From'], [to_address], msg.as_string())

# --- Salesforce helpers ---

def get_salesforce_connection(sf_domain, sf_client_id, sf_client_secret):
    response = requests.post(
        f'https://{sf_domain}/services/oauth2/token',
        data={
            'grant_type':    'client_credentials',
            'client_id':     sf_client_id,
            'client_secret': sf_client_secret
        }
    )
    if response.status_code != 200:
        raise ValueError(f'Salesforce authentication failed: {response.text}')
    token_data = response.json()
    if 'access_token' not in token_data:
        err = token_data.get('error_description', 'unknown error')
        raise ValueError(f'Salesforce did not return an access token: {err}')
    return Salesforce(
        instance_url=token_data['instance_url'],
        session_id=token_data['access_token']
    )

def parse_salesforce_error(e):
    msg = str(e)
    if 'INVALID_FIELD'   in msg: return 'Query contains an unrecognized field. Check field names and try again.'
    if 'INVALID_TYPE'    in msg: return "Query references an object that doesn't exist in this org."
    if 'MALFORMED_QUERY' in msg: return 'The SOQL query has a syntax error. Try rephrasing your request.'
    if 'INVALID_SESSION_ID'           in msg: return 'Salesforce session expired. Please reload and try again.'
    if 'REQUEST_LIMIT_EXCEEDED'       in msg: return 'Salesforce API limit reached. Please try again later.'
    if 'FIELD_CUSTOM_VALIDATION_EXCEPTION' in msg: return 'Salesforce rejected the query due to a validation rule.'
    if 'Message:' in msg: return msg.split('Message:')[-1].strip().strip('[]"\'')
    return 'Salesforce returned an error. Try rephrasing your request.'

def natural_language_to_soql(user_request):
    client  = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        system="""You are a Salesforce SOQL expert. Convert natural language requests into valid SOQL queries.

Available objects:
- Contact (Id, Name, FirstName, LastName, Email, Phone, Title, AccountId)
- Account (Id, Name, Type, Industry, Phone, BillingCity, BillingState)
- Opportunity (Id, Name, Amount, StageName, CloseDate, AccountId, OwnerId)
- Campaign (Id, Name, Status, StartDate, EndDate, Type)
- CampaignMember (Id, ContactId, CampaignId, Status)

Rules:
- Return ONLY the SOQL query, nothing else
- No explanations, no markdown, no backticks
- Always include Id and Name in SELECT when available
- Use LIMIT 200 unless the user specifies otherwise""",
        messages=[{'role': 'user', 'content': user_request}]
    )
    return message.content[0].text.strip()

# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/status', methods=['GET'])
def status():
    checks = {}
    try:
        from sqlalchemy import text
        db         = get_db_session()
        db.execute(text('SELECT 1'))
        org_count  = db.query(Organization).count()
        user_count = db.query(User).count()
        db.close()
        checks['database'] = {'ok': True, 'orgs': org_count, 'users': user_count}
    except Exception as e:
        checks['database'] = {'ok': False, 'error': str(e)}

    all_ok = all(v['ok'] for v in checks.values())
    return jsonify({
        'status':    'healthy' if all_ok else 'degraded',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'checks':    checks
    }), 200 if all_ok else 503

@app.route('/org-config', methods=['GET'])
@require_api_key
def org_config():
    org, _ = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404
    return jsonify({'org_name': org.name, 'sf_domain': org.sf_domain})

# --- User auth ---

@app.route('/register', methods=['POST'])
@require_api_key
def register():
    data     = request.json
    email    = data.get('email', '').lower().strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    org, _ = get_org_from_request()
    if not org:
        return jsonify({'error': 'Invalid API key'}), 401

    db       = get_db_session()
    existing = db.query(User).filter_by(email=email).first()
    if existing:
        db.close()
        return jsonify({'error': 'An account with that email already exists'}), 400

    user = User(
        org_id=org.id,
        email=email,
        password_hash=hash_password(password),
        role='user'
    )
    db.add(user)
    db.commit()
    token = generate_token(user.id, org.id)
    db.close()
    return jsonify({'token': token, 'email': email, 'org_name': org.name})

@app.route('/login', methods=['POST'])
def login():
    data     = request.json
    email    = data.get('email', '').lower().strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    db   = get_db_session()
    user = db.query(User).filter_by(email=email).first()

    if not user or not check_password(password, user.password_hash):
        db.close()
        return jsonify({'error': 'Invalid email or password'}), 401

    org   = db.query(Organization).filter_by(id=user.org_id).first()
    token = generate_token(user.id, org.id)
    db.close()
    return jsonify({'token': token, 'email': email, 'org_name': org.name})

# --- Password reset ---

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Always returns 200 regardless of whether the email exists (prevents enumeration).
    Required env vars: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM
    """
    data  = request.json or {}
    email = data.get('email', '').lower().strip()

    db   = get_db_session()
    user = db.query(User).filter_by(email=email).first()

    if user:
        # Invalidate any existing unused tokens for this user
        db.query(PasswordResetToken).filter_by(user_id=user.id, used=False).delete()

        raw_token  = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt()).decode()

        reset = PasswordResetToken(
            user_id    = user.id,
            token_hash = token_hash,
            expires_at = datetime.utcnow() + timedelta(hours=1)
        )
        db.add(reset)
        db.commit()

        reset_link = f'{FRONTEND_URL}/reset-password.html?token={raw_token}&id={reset.id}'

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px 24px;">
          <h2 style="color:#0D0D0D;font-size:22px;margin-bottom:8px;">Reset your password</h2>
          <p style="color:#767676;margin-bottom:24px;line-height:1.6;">
            Click the button below to set a new password. This link expires in 1 hour.
          </p>
          <a href="{reset_link}"
             style="display:inline-block;background:#E5622A;color:#fff;padding:13px 28px;
                    border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">
            Reset my password
          </a>
          <p style="color:#A0A0A0;font-size:12px;margin-top:32px;">
            If you didn't request this, you can safely ignore this email.
          </p>
        </div>"""

        try:
            send_email(email, 'Reset your askLasso password', html)
        except Exception as e:
            # Log but don't expose to caller
            print(f'[forgot-password] Email send failed for {email}: {e}')

    db.close()
    return jsonify({'ok': True})   # Always 200

@app.route('/reset-password', methods=['POST'])
def reset_password_route():
    data      = request.json or {}
    token_id  = data.get('id', '').strip()
    raw_token = data.get('token', '').strip()
    new_pass  = data.get('password', '')

    if not token_id or not raw_token or not new_pass:
        return jsonify({'error': 'Missing required fields'}), 400
    if len(new_pass) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db    = get_db_session()
    reset = db.query(PasswordResetToken).filter_by(id=token_id, used=False).first()

    if not reset:
        db.close()
        return jsonify({'error': 'Invalid or already-used reset link'}), 400
    if datetime.utcnow() > reset.expires_at:
        db.close()
        return jsonify({'error': 'This reset link has expired. Please request a new one.'}), 400
    if not bcrypt.checkpw(raw_token.encode(), reset.token_hash.encode()):
        db.close()
        return jsonify({'error': 'Invalid reset token'}), 400

    user              = db.query(User).filter_by(id=reset.user_id).first()
    user.password_hash = hash_password(new_pass)
    reset.used         = True
    db.commit()
    db.close()
    return jsonify({'ok': True})

# --- Salesforce OAuth (Authorization Code flow) ---
#
# HOW TO SET UP:
# 1. In your Salesforce Connected App, add "Authorization Code and Credentials" to OAuth flows.
# 2. Add this Callback URL: https://pulldata-production.up.railway.app/sf-oauth/callback
# 3. Ensure scopes include: openid, profile, email, api
# 4. The existing SF_CLIENT_ID / SF_CLIENT_SECRET in the org record are reused for this flow.
#
# No extra env vars needed — the per-org credentials already in the DB are used.

@app.route('/sf-oauth/start', methods=['GET'])
@require_api_key
def sf_oauth_start():
    """Returns a Salesforce authorization URL. Frontend opens this in a popup."""
    org, _ = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404

    nonce = secrets.token_urlsafe(16)
    # Clean up expired states while we're here
    now = datetime.utcnow()
    expired = [k for k, v in _oauth_states.items() if now > v['expires_at']]
    for k in expired:
        _oauth_states.pop(k, None)

    _oauth_states[nonce] = {
        'org_id':     org.id,
        'expires_at': now + timedelta(minutes=10)
    }

    redirect_uri = f'{request.host_url.rstrip("/")}/sf-oauth/callback'
    client_id    = decrypt(org.sf_client_id_encrypted)

    params = urlencode({
        'response_type': 'code',
        'client_id':     client_id,
        'redirect_uri':  redirect_uri,
        'state':         nonce,
        'scope':         'openid profile email api'
    })

    auth_url = f'https://{org.sf_domain}/services/oauth2/authorize?{params}'
    return jsonify({'auth_url': auth_url})


@app.route('/sf-oauth/callback', methods=['GET'])
def sf_oauth_callback():
    """
    Salesforce redirects here after user authentication.
    Returns an HTML page that fires window.opener.postMessage with the JWT,
    then closes itself.
    """
    code  = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    def postmsg_page(payload_js: str) -> str:
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/></head><body>
<p style="font-family:Arial;text-align:center;margin-top:100px;color:#767676;font-size:14px;">
  Completing login…
</p>
<script>
  try {{
    if (window.opener) {{
      window.opener.postMessage({payload_js}, '{FRONTEND_URL}');
    }}
  }} catch(e) {{}}
  setTimeout(() => window.close(), 600);
</script>
</body></html>"""

    if error or not code or not state:
        return postmsg_page(
            '{type:"SF_OAUTH_ERROR",error:"' + (error or 'Login was cancelled') + '"}'
        )

    state_data = _oauth_states.pop(state, None)
    if not state_data or datetime.utcnow() > state_data['expires_at']:
        return postmsg_page('{type:"SF_OAUTH_ERROR",error:"Session expired. Please try again."}')

    db  = get_db_session()
    org = db.query(Organization).filter_by(id=state_data['org_id']).first()
    if not org:
        db.close()
        return postmsg_page('{type:"SF_OAUTH_ERROR",error:"Org not found."}')

    # Exchange authorization code for access token
    redirect_uri = f'{request.host_url.rstrip("/")}/sf-oauth/callback'
    token_resp   = requests.post(
        f'https://{org.sf_domain}/services/oauth2/token',
        data={
            'grant_type':    'authorization_code',
            'code':          code,
            'client_id':     decrypt(org.sf_client_id_encrypted),
            'client_secret': decrypt(org.sf_client_secret_encrypted),
            'redirect_uri':  redirect_uri
        }
    )
    token_data = token_resp.json()

    if 'access_token' not in token_data:
        db.close()
        err = token_data.get('error_description', 'Token exchange failed')
        return postmsg_page(f'{{type:"SF_OAUTH_ERROR",error:"{err}"}}')

    # Fetch user identity from Salesforce
    identity_url = token_data.get('id') or f'https://{org.sf_domain}/services/oauth2/userinfo'
    id_resp = requests.get(
        identity_url,
        headers={'Authorization': f"Bearer {token_data['access_token']}"}
    )
    userinfo = id_resp.json()

    sf_email = (
        userinfo.get('email') or
        userinfo.get('preferred_username') or
        ''
    ).lower().strip()

    if not sf_email:
        db.close()
        return postmsg_page('{type:"SF_OAUTH_ERROR",error:"Could not retrieve email from Salesforce."}')

    # Find or create user, linked to this org
    user = db.query(User).filter_by(email=sf_email).first()
    if not user:
        user = User(
            org_id        = org.id,
            email         = sf_email,
            # Random unusable password — account can only be accessed via SF OAuth or reset flow
            password_hash = hash_password(secrets.token_urlsafe(32)),
            role          = 'user'
        )
        db.add(user)
        db.commit()

    jwt_token = generate_token(user.id, org.id)
    org_name  = org.name
    db.close()

    # Safely escape values for inline JS
    safe_token   = jwt_token.replace('"', '')
    safe_email   = sf_email.replace('"', '').replace("'", '')
    safe_orgname = org_name.replace('"', '').replace("'", '')

    payload = (
        f'{{type:"SF_OAUTH_SUCCESS",'
        f'token:"{safe_token}",'
        f'email:"{safe_email}",'
        f'org_name:"{safe_orgname}"}}'
    )
    return postmsg_page(payload)

# --- Session routes ---

@app.route('/sessions', methods=['GET'])
@require_api_key
def list_sessions():
    _, user_id = get_org_from_request()
    if not user_id:
        return jsonify({'sessions': []})

    db       = get_db_session()
    sessions = (
        db.query(ChatSession)
        .filter_by(user_id=user_id)
        .order_by(ChatSession.created_at.desc())
        .limit(50)
        .all()
    )
    result = [
        {'id': s.id, 'title': s.title, 'created_at': s.created_at.isoformat()}
        for s in sessions
    ]
    db.close()
    return jsonify({'sessions': result})

@app.route('/sessions/<session_id>/messages', methods=['GET'])
@require_api_key
def get_session_messages(session_id):
    _, user_id = get_org_from_request()
    if not user_id:
        return jsonify({'error': 'Login required'}), 401

    db      = get_db_session()
    session = db.query(ChatSession).filter_by(id=session_id, user_id=user_id).first()
    if not session:
        db.close()
        return jsonify({'error': 'Session not found'}), 404

    messages = (
        db.query(Message)
        .filter_by(session_id=session_id)
        .order_by(Message.created_at.asc())
        .all()
    )
    result = [
        {
            'id':         m.id,
            'role':       m.role,
            'content':    m.content,
            'soql':       m.soql,
            'created_at': m.created_at.isoformat()
        }
        for m in messages
    ]
    db.close()
    return jsonify({'messages': result})

# --- Ask / Confirm ---

@app.route('/ask', methods=['POST'])
@require_api_key
def ask():
    data         = request.json
    user_request = data.get('request')
    session_id   = data.get('session_id')

    if not user_request:
        return jsonify({'error': 'No request provided'}), 400

    _, user_id = get_org_from_request()

    allowed, used, limit = check_rate_limit(user_id)
    if not allowed:
        return jsonify({
            'error': f'Daily query limit reached ({limit} queries/day). Resets at midnight UTC.'
        }), 429

    soql = natural_language_to_soql(user_request)

    if user_id:
        db = get_db_session()

        if not session_id:
            title   = user_request[:50] + ('…' if len(user_request) > 50 else '')
            session = ChatSession(user_id=user_id, title=title)
            db.add(session)
            db.commit()
            session_id = session.id

        db.add(Message(session_id=session_id, role='user', content=user_request))
        db.add(Message(
            session_id=session_id,
            role='assistant',
            content="Here's the query I'll run — does this look right?",
            soql=soql
        ))
        db.commit()
        db.close()

    return jsonify({
        'soql':       soql,
        'session_id': session_id,
        'message':    "Here's the query I'll run — does this look right?",
        'usage':      {'used': used + 1, 'limit': limit}
    })

@app.route('/confirm', methods=['POST'])
@require_api_key
def confirm():
    data       = request.json
    soql       = data.get('soql')
    session_id = data.get('session_id')

    if not soql:
        return jsonify({'error': 'No SOQL query provided'}), 400

    org, user_id = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404

    try:
        sf     = get_salesforce_connection(
            org.sf_domain,
            decrypt(org.sf_client_id_encrypted),
            decrypt(org.sf_client_secret_encrypted)
        )
        result = sf.query(soql)
        total  = result['totalSize']
    except SalesforceError as e:
        return jsonify({'error': parse_salesforce_error(e)}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Unexpected error connecting to Salesforce. Please try again.'}), 500

    # Save result message — role='result', records JSON stored in soql column
    # This lets renderHistoryMessages re-build the full table on session reload.
    if user_id and session_id:
        plural = 's' if total != 1 else ''
        db     = get_db_session()
        db.add(Message(
            session_id = session_id,
            role       = 'result',
            content    = f'Returned {total} record{plural}.',
            soql       = json.dumps(result['records'])  # persists table data
        ))
        db.commit()
        db.close()

    return jsonify({'records': result['records'], 'total': total})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))