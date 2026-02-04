from qiskit import QuantumCircuit


def grover_circuit(num_qubits: int = 2) -> QuantumCircuit:
    if num_qubits < 2:
        raise ValueError("Grover requires at least 2 qubits.")

    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))

    # Oracle for |11...1>
    qc.cz(num_qubits - 2, num_qubits - 1)

    # Diffusion operator
    qc.h(range(num_qubits))
    qc.x(range(num_qubits))
    qc.h(num_qubits - 1)
    qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
    qc.h(num_qubits - 1)
    qc.x(range(num_qubits))
    qc.h(range(num_qubits))

    qc.measure(range(num_qubits), range(num_qubits))
    return qc


def deutsch_jozsa_circuit(num_qubits: int = 3, balanced: bool = True) -> QuantumCircuit:
    if num_qubits < 2:
        raise ValueError("Deutsch–Jozsa requires at least 2 qubits.")

    n = num_qubits - 1
    qc = QuantumCircuit(num_qubits, num_qubits)

    # Initialize ancilla to |1>
    qc.x(num_qubits - 1)
    qc.h(range(num_qubits))

    # Oracle: balanced uses CNOTs, constant does nothing
    if balanced:
        for i in range(n):
            qc.cx(i, num_qubits - 1)

    qc.h(range(n))
    qc.measure(range(n), range(n))
    return qc


def circuit_to_text(qc: QuantumCircuit) -> str:
    return qc.draw(output="text").single_string()
