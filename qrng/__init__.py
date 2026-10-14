"""Quantum Random Number Generator (QRNG) Module.
Uses Qiskit superposition circuits (|0> --[H]--> (|0>+|1>)/sqrt(2)) and Aer/IBM Quantum Cloud.
Derives 256-bit entropy keys using HKDF / SHA3-256 with quantum measurements.
"""
from masking.quantum_entropy import (
    QuantumEntropyGenerator,
    QuantumEntropyResult,
    get_quantum_generator,
)

__all__ = [
    "QuantumEntropyGenerator",
    "QuantumEntropyResult",
    "get_quantum_generator",
]
