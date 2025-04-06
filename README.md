# PQXDH - Post-Quantum Extended Triple Diffie-Hellman

A TypeScript implementation of the PQXDH protocol, providing quantum-resistant cryptographic security.

## Overview

PQXDH is a cryptographic protocol that combines post-quantum cryptography with the Extended Triple Diffie-Hellman (X3DH) protocol. This implementation ensures secure key exchange operations that remain protected against both classical and quantum computing threats.

## Features

- Post-quantum cryptography implementation using ML-KEM
- Extended Triple Diffie-Hellman (X3DH) protocol support
- TypeScript implementation with comprehensive type safety
- Integration with modern cryptographic libraries
- Quantum-resistant security measures

## Technical Stack

- TypeScript
- Noble Curves & Hashes
- ML-KEM (Post-quantum cryptography)
- CryptoJS

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Bashevitz/X3DH-PQ-demo.git
cd X3DH-PQ-demo
```

2. Install dependencies:

```bash
npm install
```

3. Build the project:

```bash
npm run build
```

4. Run the demonstration files:

```bash
# Run the PQXDH demonstration
npm run pq:xdh

# Run the X3DH demonstration
npm run x3dh
```

## Implementation Details

The project includes two demonstration implementations:

1. **PQXDH Implementation**: Demonstrates the post-quantum version of the Extended Triple Diffie-Hellman protocol
2. **X3DH Implementation**: Shows the classic Extended Triple Diffie-Hellman protocol implementation

The demonstration files can be found in:

- `src/pqxdh/demo.ts`
- `src/x3dh/demo.ts`

## Security Considerations

This implementation incorporates quantum-resistant cryptography using the ML-KEM algorithm, which is part of the NIST Post-Quantum Cryptography Standardization process. The protocol ensures secure key exchange operations that remain protected against both classical and quantum computing threats.

## Contributing

We welcome contributions to this project. Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

For major changes, please open an issue first to discuss the proposed modifications.

---

Developed with a focus on security and reliability
