from __future__ import annotations

from typing import Dict, Any

from qiskit_aer import AerSimulator
from qiskit import transpile

from qbench.engine.noise import build_depolarizing_noise


def run_circuit(qc, shots: int, noise_level: float) -> Dict[str, Any]:
    simulator = AerSimulator()
    noise_model = build_depolarizing_noise(qc.num_qubits, noise_level)

    tqc = transpile(qc, simulator)
    result = simulator.run(tqc, shots=shots, noise_model=noise_model).result()
    counts = result.get_counts()

    total = sum(counts.values())
    probs = {k: v / total for k, v in counts.items()}

    return {
        "counts": counts,
        "probabilities": probs,
        "shots": shots,
        "noise_level": noise_level,
    }
