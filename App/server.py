import os
import uuid
import jwt
import redis
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel

from crypto_engine import ZeroKnowledgeEngine
from database import get_db, DBUser, DBVault, DBShare

app = FastAPI(title="Zero-Knowledge Vault API")
engine = ZeroKnowledgeEngine()

REDIS_URL = os.getenv("REDIS_URL")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True) 

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("⚠️ CRITICAL: JWT_SECRET not set. Cannot start the server securely.")
    
JWT_ALGORITHM = "HS256"
security = HTTPBearer()


class RegisterRequest(BaseModel):
    username: str
    public_key_pem: str  
    encryption_public_key_pem: str 

class LoginRequest(BaseModel):
    username: str
    signature: str       

class VaultData(BaseModel):
    nonce: str
    ciphertext: str

class ShareData(BaseModel):
    recipient: str
    ephemeral_public_key: str
    nonce: str
    ciphertext: str
    sender_signature: str


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")



@app.post("/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(DBUser).filter(DBUser.username == request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")
    
    new_user = DBUser(
        username=request.username,
        public_key=request.public_key_pem,
        enc_public_key=request.encryption_public_key_pem
    )
    db.add(new_user)
    db.commit()
    
    return {"message": "Registration completed and saved to DB!"}

@app.get("/auth/challenge/{username}")
def get_challenge(username: str, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == username).first()
    nonce = str(uuid.uuid4())
    
    if user:
        redis_client.setex(f"challenge:{username}", 120, nonce)
        
    return {"challenge": nonce}

@app.post("/auth/login")
def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == request.username).first()
    
    nonce = redis_client.get(f"challenge:{request.username}")
    
    if not user or not nonce:
        raise HTTPException(status_code=401, detail="Invalid request or challenge expired")
    
    public_key_bytes = user.public_key.encode('utf-8')
    
    if not engine.verify_challenge(public_key_bytes, nonce, request.signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    redis_client.delete(f"challenge:{request.username}")
    
    token = jwt.encode(
        {"sub": request.username, "exp": datetime.utcnow() + timedelta(hours=1)}, 
        JWT_SECRET, 
        algorithm=JWT_ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/vault")
def save_vault(data: VaultData, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    vault = db.query(DBVault).filter(DBVault.username == current_user).first()
    if vault:
        vault.nonce = data.nonce
        vault.ciphertext = data.ciphertext
    else:
        vault = DBVault(username=current_user, nonce=data.nonce, ciphertext=data.ciphertext)
        db.add(vault)
    db.commit()
    return {"message": "Vault saved securely!"}

@app.get("/vault")
def get_vault(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    vault = db.query(DBVault).filter(DBVault.username == current_user).first()
    if not vault:
        raise HTTPException(status_code=404, detail="No vault found")
    return {"nonce": vault.nonce, "ciphertext": vault.ciphertext}

@app.get("/users/{target_user}/key", dependencies=[Depends(get_current_user)])
def get_user_key(target_user: str, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == target_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="Recipient user not found")
    return {"enc_public_key": user.enc_public_key}

@app.get("/users/{target_user}/identity_key", dependencies=[Depends(get_current_user)])
def get_user_identity_key(target_user: str, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == target_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"public_key": user.public_key}


@app.post("/share")
def share_secret(data: ShareData, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    recipient = db.query(DBUser).filter(DBUser.username == data.recipient).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient does not exist")
    
    new_share = DBShare(
        sender=current_user,
        recipient=data.recipient,
        ephemeral_public_key=data.ephemeral_public_key,
        nonce=data.nonce,
        ciphertext=data.ciphertext,
        sender_signature=data.sender_signature
    )
    db.add(new_share)
    db.commit()
    return {"message": "Package saved in DB and delivered!"}



@app.get("/share")
def get_my_shares(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    shares = db.query(DBShare).filter(DBShare.recipient == current_user).all()
    inbox = []
    for share in shares:
        inbox.append({
            "sender": share.sender,
            "ephemeral_public_key": share.ephemeral_public_key,
            "nonce": share.nonce,
            "ciphertext": share.ciphertext,
            "sender_signature": share.sender_signature,
            "timestamp": str(share.timestamp)
        })
    return {"inbox": inbox}