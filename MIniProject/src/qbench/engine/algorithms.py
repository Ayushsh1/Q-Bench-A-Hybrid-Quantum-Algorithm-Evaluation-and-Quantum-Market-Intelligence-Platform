from __future__ import annotations

from typing import Dict, Any

from qbench.engine.circuits import grover_circuit, deutsch_jozsa_circuit
from qbench.engine.runner import run_circuit


def run_grover(num_qubits: int, shots: int, noise_level: float) -> Dict[str, Any]:
    qc = grover_circuit(num_qubits=num_qubits)
    result = run_circuit(qc, shots=shots, noise_level=noise_level)
    result["expected_state"] = "1" * num_qubits
    return result


def run_deutsch_jozsa(
    num_qubits: int, shots: int, noise_level: float, balanced: bool
) -> Dict[str, Any]:
    qc = deutsch_jozsa_circuit(num_qubits=num_qubits, balanced=balanced)
    result = run_circuit(qc, shots=shots, noise_level=noise_level)
    result["expected_state"] = "0" * (num_qubits - 1)
    result["oracle_type"] = "balanced" if balanced else "constant"
    return result
