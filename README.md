# VPN Leak Test Backend (VLT-BE)

Backend service for VPN connection security verification, hosted on Replit.

## Quick Start

[![Run on Repl.it](https://repl.it/badge/github/vpnleaktest/VLT-BE)](https://repl.it/github/vpnleaktest/VLT-BE)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Add `.env`:
```
FLASK_APP=run.py
FLASK_ENV=development
```

## API Endpoints

### Connection Test
- **GET** `/api/test` - Returns IP and connection details

### Health Check  
- **GET** `/api/health` - Returns service status

## Security

- Rate limiting
- CORS enabled
- Request validation

## Structure
```
VLT-BE/
├── app/
│   ├── services/  # Business logic
│   ├── utils/     # Helpers
│   ├── routes.py  # Endpoints
│   └── __init__.py
├── requirements.txt
└── run.py         # Entry point
```