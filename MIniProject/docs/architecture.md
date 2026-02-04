# Q-Bench Architecture

## Overview
Q-Bench is a hybrid platform that combines a local desktop GUI with a REST API backend. The GUI is the primary user interface and consumes all data from the API. If the API is unavailable, the GUI falls back to cached datasets for market data.

## Layers
1. **GUI Layer (Tkinter)**
   - Quantum Compute Lab
   - Market & Intelligence Dashboard
   - CSV export for quantum runs

2. **API Layer (Flask)**
   - Quantum endpoints: Grover, Deutsch–Jozsa, benchmark
   - Market endpoints: companies, funding, news

3. **Engine Layer (Qiskit Aer)**
   - Circuit creation
   - Noise injection (depolarizing)
   - Measurement probabilities

4. **Analytics Layer**
   - Success probability, error rate, variance
   - Benchmark plots and CSV export

5. **Data Ingestion + Cache**
   - Local cached datasets (CSV/JSON)
   - Optional online news scraping (safe fallback)

## Offline Mode
- Market data loads from cache if API is unreachable.
- Quantum runs require the API and Qiskit Aer locally.

## Future Extensibility
- Replace Tkinter with web UI while keeping API.
- Add more algorithms (VQE, QAOA).
- Connect live market sources via scheduled ingestion.
