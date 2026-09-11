# Procfile — Process definitions for diode (SIH Unidirectional Threat Detection Enclave)
# Run with foreman, honcho, or overmind

# Main FastAPI backend server serving REST API, WebSockets, and compiled React SOC dashboard
web: python3 main.py --serve

# Background synthetic attack and benign traffic generator worker for live demonstrations
worker: python3 main.py --generate --continuous

# Development hot-reloading frontend server (proxying API calls to backend)
frontend: cd frontend && npm run dev
