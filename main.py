
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

app = FastAPI(title="CodeAlpha SQL Injection Security")

# Local database: no cloud account or payment required.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./security_records.db"
)
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class SecureRecord(Base):
    __tablename__ = "secure_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    encrypted_note: Mapped[str] = mapped_column(String, nullable=False)


Base.metadata.create_all(bind=engine)


def load_secret(env_name: str) -> str:
    value = os.getenv(env_name)
    if not value:
        raise RuntimeError(
            f"Missing {env_name}. Set it as an environment variable before starting."
        )
    return value


def get_encryption_key() -> bytes:
    # The key must be generated once and stored securely in the environment.
    import base64

    encoded = load_secret("APP_ENCRYPTION_KEY")
    key = base64.urlsafe_b64decode(encoded)
    if len(key) != 32:
        raise RuntimeError("APP_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return key


def require_capability(x_capability_token: str | None = Header(default=None)) -> None:
    expected = load_secret("APP_CAPABILITY_TOKEN")
    if not x_capability_token or not secrets.compare_digest(
        x_capability_token, expected
    ):
        raise HTTPException(status_code=401, detail="Valid capability token required")


class RecordCreate(BaseModel):
    owner: str = Field(min_length=1, max_length=100)
    note: str = Field(min_length=1, max_length=2000)


def encrypt_note(note: str) -> str:
    import base64

    aes = AESGCM(get_encryption_key())
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, note.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_note(encrypted_note: str) -> str:
    import base64

    raw = base64.urlsafe_b64decode(encrypted_note.encode("ascii"))
    nonce, ciphertext = raw[:12], raw[12:]
    return AESGCM(get_encryption_key()).decrypt(nonce, ciphertext, None).decode("utf-8")


@app.get("/")
def home():
    return {
        "project": "CodeAlpha SQL Injection Security",
        "message": "API is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/records", dependencies=[Depends(require_capability)], status_code=201)
def create_record(payload: RecordCreate):
    with SessionLocal() as session:
        record = SecureRecord(
            owner=payload.owner,
            encrypted_note=encrypt_note(payload.note),
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return {"id": record.id, "owner": record.owner, "message": "Record encrypted and saved"}


@app.get("/records/{record_id}", dependencies=[Depends(require_capability)])
def get_record(record_id: int):
    # SQLAlchemy builds a parameterized query; user input is not concatenated into SQL.
    with SessionLocal() as session:
        record = session.scalar(
            select(SecureRecord).where(SecureRecord.id == record_id)
        )
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")
        try:
            note = decrypt_note(record.encrypted_note)
        except Exception:
            raise HTTPException(status_code=500, detail="Unable to decrypt record")
        return {"id": record.id, "owner": record.owner, "note": note}
