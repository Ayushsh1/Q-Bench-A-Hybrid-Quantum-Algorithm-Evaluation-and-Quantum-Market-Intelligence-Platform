# API Endpoints

## Health
- GET /health

## Quantum
- POST /quantum/grover
- POST /quantum/deutsch-jozsa
- POST /quantum/benchmark

### Example Payload (Grover)
```json
{"num_qubits": 2, "shots": 1024, "noise_level": 0.01}
```

## Market
- GET /market/companies
- GET /market/funding
- GET /market/news
