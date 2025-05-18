# C Encryption Utility

A command-line tool for file encryption/decryption and RSA key generation supporting Blowfish, TEA, and RSA algorithms.

## Features

- **Supported Algorithms**
  - Symmetric Encryption:
    - Blowfish (CBC mode)
    - TEA (CBC mode)
  - Asymmetric Encryption:
    - RSA (key generation, encryption/decryption)
    
- **Operations**
  - File encryption/decryption
  - RSA key pair generation
  - CBC mode with random IV generation
  - PKCS7 padding for block alignment

- **Key Management**
  - Symmetric: Passphrase-based key derivation
  - RSA: PEM-style key files storage (hex encoded)

## Installation

### Prerequisites
- C compiler and CMake

### Linux (Debian/Ubuntu)
```bash
mkdir build
cd build
cmake ..
make
```