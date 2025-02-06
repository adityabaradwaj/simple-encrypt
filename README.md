# simple-encrypt

A simple encryption tool built in Rust. If you need basic symmetric-key encryption with reasonable defaults for your project, without having to wade through the forest of encryption algorithms and parameters, this tool will make your life easier. It uses the AES-GCM-256 scheme, which is considered industry-standard.

Provides both a command-line interface and library for encrypting files and data.

Example use case: You have a configuration file containing secrets like API keys, database passwords, crypto seed phrases, etc. You want to securely use these secrets during local development, and be able to deploy them to remote environments. A good way to do this is encrypt your secrets at rest in all environments, and only decrypt them in-memory in your application. This is especially important in today's world, where AI-powered IDEs are constantly sending your code (and potentially secrets) to a remote server.

## Installation

### Command Line Tool
```bash
cargo install simple-encrypt
```

### Library
Add to your `Cargo.toml`:
```toml
[dependencies]
simple-encrypt = "0.1.0"
```

## Quick Start

### Command Line
Encrypt a file:
```bash
simple-encrypt encrypt config.json config.enc
```

Decrypt a file:
```bash
simple-encrypt decrypt config.enc config.json
```

### In Your Code
```rust
use simple_encrypt::{encrypt_bytes, decrypt_bytes};

// Encrypt sensitive configuration
let config = r#"{"api_key": "secret123", "db_password": "dbpass"}"#;
let password = "your-secure-password";
let encrypted = encrypt_bytes(config.as_bytes(), password)?;

// Later, decrypt only when needed
let decrypted = decrypt_bytes(&encrypted, password)?;
let config = String::from_utf8(decrypted)?;
```

## License

MIT - See [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

