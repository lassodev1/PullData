from sqlalchemy import create_engine, Column, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from cryptography.fernet import Fernet
from datetime import datetime
import bcrypt
import os
import uuid

Base = declarative_base()

def get_engine():
    db_url = os.getenv('DATABASE_URL')
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    return create_engine(db_url)

def get_db_session():
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()

def get_fernet():
    key = os.getenv('ENCRYPTION_KEY')
    return Fernet(key.encode())

# --- Tables ---

class Organization(Base):
    __tablename__ = 'organizations'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    sf_domain = Column(String, nullable=False)
    sf_client_id_encrypted = Column(Text, nullable=False)
    sf_client_secret_encrypted = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    api_keys = relationship('ApiKey', back_populates='organization')
    users    = relationship('User', back_populates='organization')

class ApiKey(Base):
    __tablename__ = 'api_keys'
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id     = Column(String, ForeignKey('organizations.id'), nullable=False)
    key_hash   = Column(String, nullable=False)
    label      = Column(String)
    active     = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship('Organization', back_populates='api_keys')

class User(Base):
    __tablename__ = 'users'
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id        = Column(String, ForeignKey('organizations.id'), nullable=False)
    email         = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    role          = Column(String, default='user')
    created_at    = Column(DateTime, default=datetime.utcnow)

    organization = relationship('Organization', back_populates='users')
    sessions     = relationship('ChatSession', back_populates='user')

class ChatSession(Base):
    __tablename__ = 'sessions'
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, ForeignKey('users.id'), nullable=False)
    title      = Column(String, default='New session')
    created_at = Column(DateTime, default=datetime.utcnow)

    user     = relationship('User', back_populates='sessions')
    messages = relationship('Message', back_populates='session')

class Message(Base):
    __tablename__ = 'messages'
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey('sessions.id'), nullable=False)
    role       = Column(String, nullable=False)   # 'user' | 'assistant' | 'result'
    content    = Column(Text, nullable=False)
    soql       = Column(Text)  # SOQL for assistant msgs; JSON records array for role='result'
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship('ChatSession', back_populates='messages')

class PasswordResetToken(Base):
    """One-time tokens for password reset emails. New table — created by init_db()."""
    __tablename__ = 'password_reset_tokens'
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String, nullable=False)   # bcrypt hash of the raw URL token
    expires_at = Column(DateTime, nullable=False)
    used       = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship('User')

# --- Helper functions ---

def encrypt(value):
    return get_fernet().encrypt(value.encode()).decode()

def decrypt(value):
    return get_fernet().decrypt(value.encode()).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)   # creates missing tables; existing tables untouched
    print("Database tables created/verified.")