from qiskit_aer.noise import NoiseModel, depolarizing_error


def build_depolarizing_noise(num_qubits: int, noise_level: float) -> NoiseModel:
    if noise_level < 0 or noise_level > 1:
        raise ValueError("noise_level must be between 0 and 1.")

    noise_model = NoiseModel()
    if noise_level == 0:
        return noise_model

    error_1 = depolarizing_error(noise_level, 1)
    error_2 = depolarizing_error(noise_level, 2)

    noise_model.add_all_qubit_quantum_error(error_1, ["h", "x"])
    noise_model.add_all_qubit_quantum_error(error_2, ["cx", "cz"])
    return noise_model
