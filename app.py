from flask import Flask, request, jsonify
from flask_cors import CORS
from simple_salesforce import Salesforce
from dotenv import load_dotenv
import anthropic
import requests
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

def get_salesforce_connection():
    response = requests.post(
        'https://orgfarm-cde7fad80c-dev-ed.develop.my.salesforce.com/services/oauth2/token',
        data={
            'grant_type': 'client_credentials',
            'client_id': os.getenv('SF_CLIENT_ID'),
            'client_secret': os.getenv('SF_CLIENT_SECRET')
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

@app.route('/ask', methods=['POST'])
def ask():
    data = request.json
    user_request = data.get('request')

    if not user_request:
        return jsonify({'error': 'No request provided'}), 400

    soql = natural_language_to_soql(user_request)
    
    return jsonify({
        'soql': soql,
        'message': f"Here's the query I'll run — does this look right?",
    })

@app.route('/confirm', methods=['POST'])
def confirm():
    data = request.json
    soql = data.get('soql')

    if not soql:
        return jsonify({'error': 'No SOQL query provided'}), 400

    sf = get_salesforce_connection()
    result = sf.query(soql)
    return jsonify({
        'records': result['records'],
        'total': result['totalSize']
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=True, port=3000)