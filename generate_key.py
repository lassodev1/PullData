from dotenv import load_dotenv
load_dotenv()

from models import get_db_session, Organization, ApiKey, encrypt, hash_password
import bcrypt
import secrets
import sys

def generate_api_key(org_name, sf_domain, sf_client_id, sf_client_secret):
    db = get_db_session()

    # Create the organization
    org = Organization(
        name=org_name,
        sf_domain=sf_domain,
        sf_client_id_encrypted=encrypt(sf_client_id),
        sf_client_secret_encrypted=encrypt(sf_client_secret)
    )
    db.add(org)
    db.flush()

    # Generate a raw key the institution will use
    raw_key = f"pd_{secrets.token_urlsafe(32)}"

    # Store only the hash
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    api_key = ApiKey(
        org_id=org.id,
        key_hash=hashed,
        label=org_name
    )
    db.add(api_key)
    db.commit()

    print(f"\nOrganization created: {org_name}")
    print(f"Org ID: {org.id}")
    print(f"\nAPI Key (share this with the institution — shown once):")
    print(f"\n  {raw_key}\n")

if __name__ == '__main__':
    generate_api_key(
        org_name="Westmont College",
        sf_domain="orgfarm-cde7fad80c-dev-ed.develop.my.salesforce.com",
        sf_client_id=input("Paste SF_CLIENT_ID: "),
        sf_client_secret=input("Paste SF_CLIENT_SECRET: ")
    )