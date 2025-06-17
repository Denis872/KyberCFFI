# KyberCFFI

**Python CFFI buildings for post-quantum cryptography algorithm Kyber**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/kybercffi.svg)](https://pypi.org/project/kybercffi/)

## Description

KyberCFFI provides Python bindings for the reference implementation of the Kyber cryptographic algorithm, winner of the NIST post-quantum cryptography competition. The library uses CFFI to efficiently interact with the original Kyber C code.

### Supported variants

- **Kyber512** - Security level 1 (equivalent to AES-128)
- **Kyber768** - Security level 3 (equivalent to AES-192)  
- **Kyber1024** - Security level 5 (equivalent to AES-256)

## Installation

```bash
pip install kybercffi
```

### Requirements

- Python >= 3.8
- CFFI >= 1.15.0
- C compiler  

## Quick start

```python
import kybercffi

# Create a Kyber768 instance
kyber = kybercffi.Kyber768()

# Generate key pair
public_key, secret_key = kyber.generate_keypair()

# Encapsulation (create shared secret)
ciphertext, shared_secret = kyber.encapsulate(public_key)

# Decapsulation (recover shared secret)
recovered_secret = kyber.decapsulate(ciphertext, secret_key)

# Verification
assert shared_secret == recovered_secret
print("Kyber работает корректно!")
```

## Convenient functions

```python
from kybercffi import generate_keypair, encapsulate, decapsulate

# Generate keys with specified security level
pk, sk = generate_keypair(security_level=3)  # Kyber768

# Encapsulation
ct, ss = encapsulate(pk, security_level=3)

# Decapsulation
ss2 = decapsulate(ct, sk, security_level=3)
```

## Factory method

```python
# Creating an instance via the factory
kyber512 = kybercffi.KyberKEM.create(security_level=1)   # Kyber512
kyber768 = kybercffi.KyberKEM.create(security_level=3)   # Kyber768
kyber1024 = kybercffi.KyberKEM.create(security_level=5)  # Kyber1024
```

## Information about variants

```python
# Getting information about all variants
info = kybercffi.get_kyber_info()
print(info)

# Getting version information
version_info = kybercffi.get_version_info()
print(version_info)
```

## Size of key and encrypted text

| Variant   | Public key | Secret key | Ciphertext | Shared secret |
|-----------|---------------|----------------|---------------------|--------------|
| Kyber512  | 800 bytes      | 1632 bytes     | 768 bytes            | 32 bytes     |
| Kyber768  | 1184 bytes    | 2400 bytes      | 1088 bytes           | 32 bytes     |
| Kyber1024 | 1568 bytes     | 3168 bytes      | 1568 bytes           | 32 bytes     |

## Features

- ⚡ **High performance** - uses an optimized C implementation
- 🛡️ **Post-quantum security** - resistant to attacks from quantum computers
- 🌐 **Cross-platform** - works on Windows, Linux, macOS
- 📦 **Easy installation** - automatic compilation during installation
- 🔒 **Cryptographically secure** - based on the NIST reference implementation

## License

The project is distributed under the MIT license. See the [LICENSE](LICENSE) file for details.

## Author

**Denis Magnitov**
- Email: pm13.magnitov@gmail.com
- GitHub: [Denis872](https://github.com/Denis872)

## Links

- [Repository](https://github.com/Denis872/KyberCFFI)
- [PyPI](https://pypi.org/project/kybercffi/)
- [Official Kyber Specification](https://pq-crystals.org/kyber/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Support

If you encounter any problems or have any questions, please:
1. Check [existing Issues](https://github.com/Denis872/KyberCFFI/issues)
2. Create a new Issue with a detailed description of the problem
3. Specify the version of Python, OS, and kybercffi
