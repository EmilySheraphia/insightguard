# InsightGuard — Insider Threat Detection System

Real-time insider threat detection using User Behaviour Analytics (UBA),
machine learning anomaly detection, and Explainable AI.

## Architecture (6-Layer)

```
data_acquisition/   →  Layer 1: Log collection (login, file, email, USB, web)
data_processing/    →  Layer 2: ETL pipeline, cleaning, normalization
feature_engineering/→  Layer 3: Behavioral feature extraction
ai_analytics/       →  Layer 4: Isolation Forest + LOF anomaly detection
explainability/     →  Layer 5: LIME-based AI explanation engine
application/        →  Layer 6: Flask REST API + dashboard controller
storage/            →  Storage layer: SQLite database (activity logs, alerts)
tests/              →  Full test suite
```

## Quick Start

```bash
pip install flask scikit-learn numpy pandas

# Run self-test
python tests/test_all.py

# Start API server
python application/app.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/events | Analyse a single activity log event |
| POST | /api/events/batch | Analyse batch of events (max 500) |
| GET | /api/users/{id}/risk | Get user risk profile |
| DELETE | /api/users/{id}/risk | Reset user risk profile |
| GET | /api/alerts | List recent alerts (filterable) |
| GET | /api/alerts/{id}/explain | LIME explanation for alert |
| GET | /api/users/{id}/timeline | Full activity timeline |
| GET | /api/stats | System-wide detection statistics |
| GET | /api/stream | Server-Sent Events live stream |
| GET | /healthz | Health + model readiness |

## Technology Stack

- **Language**: Python 3.12
- **Backend API**: Flask
- **ML Models**: Isolation Forest + Local Outlier Factor (scikit-learn)
- **Explainability**: LIME (built-in implementation)
- **Database**: SQLite
- **Data Processing**: Pandas + NumPy
