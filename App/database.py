import os
import datetime
from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL"
)
#"postgresql://admin:super_password_db@localhost:5432/vault_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class DBUser(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True) 
    public_key = Column(Text, nullable=False)
    enc_public_key = Column(Text, nullable=False)

class DBChallenge(Base):
    __tablename__ = "challenges"
    username = Column(String, primary_key=True, index=True)
    nonce = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)

class DBVault(Base):
    __tablename__ = "vaults"
    username = Column(String, primary_key=True, index=True)
    nonce = Column(String, nullable=False)
    ciphertext = Column(Text, nullable=False)

class DBShare(Base):
    __tablename__ = "shares"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, index=True, nullable=False) 
    ephemeral_public_key = Column(Text, nullable=False)
    nonce = Column(String, nullable=False)
    ciphertext = Column(Text, nullable=False)
    sender_signature = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()