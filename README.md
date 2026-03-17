# ScamShield API

A production-style, developer-facing scam detection service built with FastAPI.
ScamShield analyzes suspicious content across multiple channels — phone transcripts,
emails, audio recordings, and live streaming sessions — and returns structured
risk scores and actionable guidance.

---

## Features

- **Transcript analysis** — Submit call or voicemail text and receive a risk score, matched signals, and recommended action.
- **Email analysis** — Detect phishing, spoofed senders, suspicious links, and social engineering in email content.
- **Audio analysis** — Upload audio files; the service transcribes and analyzes them end-to-end. Mock provider included; Whisper-ready.
- **Session streaming** — Start a session, submit rolling text chunks (every few seconds), and receive live risk updates for ongoing calls.
- **Heuristic detection engine** — 20+ weighted rules covering urgency, fear, impersonation, OTP theft, payment fraud, remote access, and more.
- **Clean architecture** — Separation of concerns across domain, services, repositories, schemas, and routes.
- **Abstracted dependencies** — Transcription provider, session store, and detection engine are all injectable and swappable.

---

## Architecture Overview

```
app/
├── main.py                        # Application factory (FastAPI app + routers)
├── core/
│   ├── config.py                  # Pydantic Settings — all env vars in one place
│   ├── logging.py                 # Structured logging setup
│   └── dependencies.py            # Dependency injection factories
├── api/routes/
│   ├── health.py                  # GET /health
│   ├── info.py                    # GET /api/v1/info
│   ├── analyze.py                 # POST /api/v1/analyze/{transcript,email,audio}
│   └── sessions.py                # POST /api/v1/session/{start,chunk,end}
├── schemas/                       # Pydantic request/response models
│   ├── common.py
│   ├── transcript.py
│   ├── email.py
│   ├── audio.py
│   └── session.py
├── services/
│   ├── analysis/
│   │   ├── engine.py              # Stateless scoring engine
│   │   ├── rules.py               # 20+ declarative DetectionRule definitions
│   │   ├── models.py              # Internal engine models (DetectionRule, RuleMatch)
│   │   ├── normalizers.py         # Text normalization pipeline
│   │   └── email_checks.py        # Sender/domain/link heuristics
│   ├── transcription/
│   │   ├── base.py                # TranscriptionService abstract base
│   │   ├── mock.py                # MockTranscriptionService (default in MVP)
│   │   └── whisper.py             # WhisperTranscriptionService (production-ready scaffold)
│   └── sessions/
│       └── manager.py             # Session lifecycle business logic
├── repositories/
│   ├── session_repository.py      # Abstract repository interface
│   └── in_memory_session_repository.py   # MVP in-memory implementation
├── domain/
│   └── entities.py                # Core domain objects (AnalysisResult, Session, etc.)
└── utils/
    ├── text.py                    # General text helpers
    └── files.py                   # Audio file validation

tests/
├── conftest.py
├── test_health.py
├── test_transcript_analysis.py
├── test_email_analysis.py
├── test_sessions.py
└── test_audio_analysis.py
```

**Key design decisions:**

- **DetectionEngine is stateless.** It receives text, applies rules, and returns a result. It has no knowledge of HTTP, sessions, or persistence.
- **Rules are declarative.** Each `DetectionRule` specifies patterns, weight, category, and reason. Adding a new signal means adding one entry to `rules.py`.
- **Repository pattern for sessions.** `SessionRepository` is an abstract interface; the in-memory implementation can be replaced with DynamoDB or Redis without touching route or service code.
- **Transcription is injectable.** `TranscriptionService` is an abstract base; `MockTranscriptionService` is used by default and `WhisperTranscriptionService` is wired up for production use.
- **Pydantic v2 throughout.** All request bodies and responses are validated and serialized by Pydantic models. Aliases (`riskScore`, `matchedSignals`, etc.) produce a camelCase JSON API.

---

## Setup

### Requirements

- Python 3.12+
- pip

### Install

```bash
# 1. Clone the repo
git clone <repo-url>
cd scam_shield

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
# .venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and configure environment variables
cp .env.example .env
# Edit .env as needed (defaults work for local dev)
```

---

## Run Locally

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs are available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/api/v1/info` | Service metadata and supported channels |
| `POST` | `/api/v1/analyze/transcript` | Analyze call/voicemail transcript text |
| `POST` | `/api/v1/analyze/email` | Analyze email for phishing and scam signals |
| `POST` | `/api/v1/analyze/audio` | Upload audio file for transcription + analysis |
| `POST` | `/api/v1/session/start` | Start a real-time session |
| `POST` | `/api/v1/session/{id}/chunk` | Submit a text chunk to an active session |
| `POST` | `/api/v1/session/{id}/end` | End a session and retrieve final analysis |

---

## Example Requests

### Analyze a transcript

```bash
curl -X POST http://localhost:8000/api/v1/analyze/transcript \
  -H "Content-Type: application/json" \
  -d '{
    "text": "This is the bank security department. Your account will be suspended. Read me the verification code.",
    "context": {
      "source": "call_transcript",
      "claimedCaller": "Bank of America"
    }
  }'
```

### Analyze an email

```bash
curl -X POST http://localhost:8000/api/v1/analyze/email \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify your account now",
    "fromAddress": "support@amaz0n-login-security.com",
    "body": "Please click the link below and confirm your password immediately.",
    "links": ["http://amaz0n-login-security.com/verify"]
  }'
```

### Analyze an audio file

```bash
curl -X POST http://localhost:8000/api/v1/analyze/audio \
  -F "file=@/path/to/recording.wav"
```

> **Note:** Audio transcription is mocked by default in the MVP.  
> Set `ENABLE_MOCK_TRANSCRIPTION=false` and `OPENAI_API_KEY=<your-key>` in `.env` to use Whisper.

### Session-based rolling analysis

```bash
# 1. Start session
SESSION=$(curl -s -X POST http://localhost:8000/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{"channel":"call"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['sessionId'])")

# 2. Submit chunk
curl -X POST http://localhost:8000/api/v1/session/$SESSION/chunk \
  -H "Content-Type: application/json" \
  -d '{"text": "This is the IRS. You owe back taxes."}'

# 3. Submit another chunk
curl -X POST http://localhost:8000/api/v1/session/$SESSION/chunk \
  -H "Content-Type: application/json" \
  -d '{"text": "Pay immediately by gift card or you will be arrested."}'

# 4. End session
curl -X POST http://localhost:8000/api/v1/session/$SESSION/end
```

---

## Testing

```bash
# Run the full test suite
pytest

# Run with coverage
pip install pytest-cov
pytest --cov=app --cov-report=term-missing

# Run a specific file
pytest tests/test_transcript_analysis.py -v
```

---

## Detection Signals

The engine currently detects 20+ signal categories:

| Category | Example Phrases |
|----------|----------------|
| Urgency | "act now", "immediately", "urgent", "last chance" |
| Fear / Legal Threat | "warrant", "arrest", "criminal charges", "legal action" |
| Account Suspension | "account will be suspended", "unusual activity detected" |
| Bank Impersonation | "bank security department", "fraud department" |
| IRS / Gov Impersonation | "IRS", "social security administration", "FBI" |
| Tech Support Scam | "Microsoft support", "your computer is infected", "remote access" |
| OTP Theft | "read me the code", "verification code", "one-time password" |
| Sensitive Info Request | "social security number", "confirm your password", "date of birth" |
| Payment Fraud – Gift Cards | "gift card", "iTunes card", "Google Play card" |
| Payment Fraud – Crypto | "bitcoin", "cryptocurrency payment", "wallet address" |
| Payment Fraud – Wire | "wire transfer", "Zelle", "Western Union" |
| Refund Scam | "you are owed a refund", "overpaid", "send back the difference" |
| Remote Access | "TeamViewer", "AnyDesk", "share your screen", "give me access" |
| Phishing Links | suspicious TLDs, IP-based URLs, brand-spoofed domains |
| Manipulation | "don't tell anyone", "keep this confidential", "do not hang up" |

---

## Future Production Roadmap

| Area | Upgrade |
|------|---------|
| **Session store** | Replace `InMemorySessionRepository` with `RedisSessionRepository` or `DynamoDBSessionRepository` for multi-process deployments |
| **Transcription** | Set `ENABLE_MOCK_TRANSCRIPTION=false` and configure `OPENAI_API_KEY` to activate `WhisperTranscriptionService` |
| **Authentication** | Add API key middleware or OAuth2/JWT for developer-facing access control |
| **Rate limiting** | Add `slowapi` or an API gateway-level rate limiter per API key |
| **Background jobs** | Offload audio transcription to a Celery/SQS worker to avoid request timeouts |
| **Persistence & analytics** | Store analysis results in DynamoDB/PostgreSQL for trend analysis and audit trails |
| **ML scoring** | Replace or augment heuristic rules with a trained classifier (scikit-learn, HuggingFace) |
| **Webhooks** | Allow clients to register webhook URLs for async analysis completion notifications |
| **SMS/WhatsApp** | Add a `/analyze/sms` endpoint and a Twilio integration for mobile threat detection |
| **Monitoring** | Add Prometheus metrics endpoint and OpenTelemetry tracing |
| **CI/CD** | GitHub Actions pipeline with pytest, linting (ruff), and deployment to AWS Lambda / ECS |

---

## License

MIT
