from flask import Flask, request, jsonify
from flask_cors import CORS
from simple_salesforce import Salesforce, SalesforceError
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from models import (
    get_db_session, ApiKey, Organization, User, ChatSession, Message,
    decrypt, hash_password, check_password
)
import bcrypt
import jwt
import anthropic
import requests
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

ALLOWED_ORIGIN    = os.getenv('ALLOWED_ORIGIN', 'https://asklasso.com')
DAILY_QUERY_LIMIT = int(os.getenv('DAILY_QUERY_LIMIT', '100'))

# --- CORS headers ---

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

    # Try JWT first
    try:
        payload = decode_token(token)
        db      = get_db_session()
        org     = db.query(Organization).filter_by(id=payload['org_id']).first()
        user_id = payload['user_id']
        db.close()
        return org, user_id
    except jwt.InvalidTokenError:
        pass

    # Fall back to API key
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
    """Returns (allowed: bool, used: int, limit: int)"""
    if not user_id:
        return True, 0, DAILY_QUERY_LIMIT  # API key auth — no per-user limit enforced

    db          = get_db_session()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Count user messages sent today across all sessions belonging to this user
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
    """Turn a SalesforceError into a human-readable message."""
    msg = str(e)
    if 'INVALID_FIELD' in msg:
        return 'Query contains an unrecognized field. Check the field names and try again.'
    if 'INVALID_TYPE' in msg:
        return "Query references an object that doesn't exist in this Salesforce org."
    if 'MALFORMED_QUERY' in msg:
        return 'The SOQL query has a syntax error. Try rephrasing your request.'
    if 'INVALID_SESSION_ID' in msg:
        return 'Salesforce session expired. Please reload and try again.'
    if 'REQUEST_LIMIT_EXCEEDED' in msg:
        return 'Salesforce API limit reached. Please try again later.'
    if 'FIELD_CUSTOM_VALIDATION_EXCEPTION' in msg:
        return 'Salesforce rejected the query due to a validation rule.'
    # Try to extract just the message portion from the exception string
    if 'Message:' in msg:
        return msg.split('Message:')[-1].strip().strip('[]"\'')
    return 'Salesforce returned an error. Try rephrasing your request.'

def natural_language_to_soql(user_request):
    client  = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        system="""You are a Salesforce SOQL expert. Your job is to convert natural language requests into valid SOQL queries.

The Salesforce org has these standard objects available:
- Contact (fields: Id, Name, FirstName, LastName, Email, Phone, Title, AccountId)
- Account (fields: Id, Name, Type, Industry, Phone, BillingCity, BillingState)
- Opportunity (fields: Id, Name, Amount, StageName, CloseDate, AccountId, OwnerId)
- Campaign (fields: Id, Name, Status, StartDate, EndDate, Type)
- CampaignMember (fields: Id, ContactId, CampaignId, Status)

Rules:
- Return ONLY the SOQL query, nothing else
- No explanations, no markdown, no backticks
- Always include Id and Name in SELECT when available
- Use LIMIT 200 unless the user specifies otherwise""",
        messages=[{'role': 'user', 'content': user_request}]
    )
    return message.content[0].text.strip()

# --- Routes ---

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/status', methods=['GET'])
def status():
    """Health dashboard — checks DB connectivity and returns basic stats."""
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
    org, user_id = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404
    return jsonify({'org_name': org.name, 'sf_domain': org.sf_domain})

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

    # Rate limit check
    allowed, used, limit = check_rate_limit(user_id)
    if not allowed:
        return jsonify({
            'error': f'Daily query limit reached ({limit} queries/day). Resets at midnight UTC.'
        }), 429

    soql = natural_language_to_soql(user_request)

    if user_id:
        db = get_db_session()

        if not session_id:
            title   = user_request[:50] + ('...' if len(user_request) > 50 else '')
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

    if user_id and session_id:
        plural  = 's' if total != 1 else ''
        db      = get_db_session()
        db.add(Message(
            session_id=session_id,
            role='assistant',
            content=f'Returned {total} record{plural}.'
        ))
        db.commit()
        db.close()

    return jsonify({'records': result['records'], 'total': total})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))