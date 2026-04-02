from flask import Flask, request, jsonify
from flask_cors import CORS
from simple_salesforce import Salesforce
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from models import (
    get_db_session, ApiKey, Organization, User,
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
 
# --- CORS headers ---
 
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response
 
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response
 
# --- Auth helpers ---
 
def generate_token(user_id, org_id):
    payload = {
        'user_id': user_id,
        'org_id': org_id,
        'exp': datetime.utcnow() + timedelta(days=30)
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
        db = get_db_session()
        org = db.query(Organization).filter_by(id=payload['org_id']).first()
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
 
        # Accept JWT tokens
        try:
            decode_token(token)
            return f(*args, **kwargs)
        except jwt.InvalidTokenError:
            pass
 
        # Accept API keys
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
 
# --- Salesforce helpers ---
 
def get_salesforce_connection(sf_domain, sf_client_id, sf_client_secret):
    response = requests.post(
        f'https://{sf_domain}/services/oauth2/token',
        data={
            'grant_type': 'client_credentials',
            'client_id': sf_client_id,
            'client_secret': sf_client_secret
        }
    )
    token_data = response.json()
    return Salesforce(
        instance_url=token_data['instance_url'],
        session_id=token_data['access_token']
    )
 
def natural_language_to_soql(user_request):
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
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
        messages=[
            {"role": "user", "content": user_request}
        ]
    )
    return message.content[0].text.strip()
 
# --- Routes ---
 
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})
 
@app.route('/org-config', methods=['GET'])
@require_api_key
def org_config():
    org, user_id = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404
    return jsonify({
        'org_name': org.name,
        'sf_domain': org.sf_domain
    })
 
@app.route('/register', methods=['POST'])
@require_api_key
def register():
    data = request.json
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
 
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
 
    org, _ = get_org_from_request()
    if not org:
        return jsonify({'error': 'Invalid API key'}), 401
 
    db = get_db_session()
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
 
    return jsonify({
        'token': token,
        'email': email,
        'org_name': org.name
    })
 
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
 
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
 
    db = get_db_session()
    user = db.query(User).filter_by(email=email).first()
 
    if not user or not check_password(password, user.password_hash):
        db.close()
        return jsonify({'error': 'Invalid email or password'}), 401
 
    org = db.query(Organization).filter_by(id=user.org_id).first()
    token = generate_token(user.id, org.id)
    db.close()
 
    return jsonify({
        'token': token,
        'email': email,
        'org_name': org.name
    })
 
@app.route('/ask', methods=['POST'])
@require_api_key
def ask():
    data = request.json
    user_request = data.get('request')
 
    if not user_request:
        return jsonify({'error': 'No request provided'}), 400
 
    soql = natural_language_to_soql(user_request)
    return jsonify({
        'soql': soql,
        'message': "Here's the query I'll run — does this look right?",
    })
 
@app.route('/confirm', methods=['POST'])
@require_api_key
def confirm():
    data = request.json
    soql = data.get('soql')
 
    if not soql:
        return jsonify({'error': 'No SOQL query provided'}), 400
 
    org, user_id = get_org_from_request()
    if not org:
        return jsonify({'error': 'Org not found'}), 404
 
    sf = get_salesforce_connection(
        org.sf_domain,
        decrypt(org.sf_client_id_encrypted),
        decrypt(org.sf_client_secret_encrypted)
    )
 
    result = sf.query(soql)
    return jsonify({
        'records': result['records'],
        'total': result['totalSize']
    })
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))