import requests
from simple_salesforce import Salesforce
from dotenv import load_dotenv
import os

load_dotenv()

response = requests.post('https://orgfarm-cde7fad80c-dev-ed.develop.my.salesforce.com/services/oauth2/token', data={
    'grant_type': 'client_credentials',
    'client_id': os.getenv('SF_CLIENT_ID'),
    'client_secret': os.getenv('SF_CLIENT_SECRET')
})

token_data = response.json()
print("Login response:", token_data)

if 'access_token' in token_data:
    sf = Salesforce(
        instance_url=token_data['instance_url'],
        session_id=token_data['access_token']
    )
    result = sf.query("SELECT Id, Name FROM Contact LIMIT 5")
    print("Contacts:", result['records'])
else:
    print("Auth failed:", token_data)