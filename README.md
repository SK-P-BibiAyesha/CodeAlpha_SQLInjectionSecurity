
# CodeAlpha SQL Injection Security

A Python-based security application developed as part of the CodeAlpha Cloud Computing Internship.

## Project Overview

This project demonstrates security techniques for protecting application records, including parameterized database queries, capability-token authentication, and AES-256-GCM encryption.

## Features

- **SQL Injection Protection:** Uses SQLAlchemy ORM queries instead of directly concatenating user input into SQL statements.
- **Capability-Based Authentication:** Protects record endpoints using a secret token in the `X-Capability-Token` HTTP header.
- **AES-256-GCM Encryption:** Encrypts sensitive notes before storing them in the database.
- **Secure Record Retrieval:** Decrypts stored notes when an authorized request retrieves a record.
- **Input Validation:** Uses Pydantic to validate incoming record data.
- **Automated Testing:** Includes tests for authentication, encryption, record retrieval, and SQL injection-related inputs.

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Cryptography (AES-256-GCM)
- Pytest

## Project Structure

```text
CodeAlpha_SQLInjectionSecurity/
├── main.py
├── test_main.py
├── check_storage.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd CodeAlpha_SQLInjectionSecurity
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure security secrets

Generate an AES-256 encryption key:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Generate a capability token:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set both values in PowerShell:

```powershell
$env:APP_ENCRYPTION_KEY = "YOUR_GENERATED_ENCRYPTION_KEY"
$env:APP_CAPABILITY_TOKEN = "YOUR_GENERATED_CAPABILITY_TOKEN"
```

Keep these secrets private. Never commit real secret values to GitHub.

### 6. Start the application

```powershell
python -m uvicorn main:app --reload
```

Open the API documentation:

http://127.0.0.1:8000/docs

## Running Tests

Run:

```powershell
python -m pytest -v
```

Current test results:

- 5 tests passed.
- Authentication protection verified.
- Encrypted record storage and retrieval verified.
- SQL injection-related input handling tested.

## Database and Encryption

The application uses SQLite for local storage. Sensitive note contents are encrypted using AES-256-GCM before being saved.

The encryption key is supplied through an environment variable and is not stored in the source code.

## Internship Project

**Organization:** CodeAlpha  
**Domain:** Cloud Computing  
**Project:** SQL Injection Security

