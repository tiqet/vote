# Cryptographically Secure Voting System

A minimal foundation for a cryptographically secure voting system, built incrementally.

## Current Status

This is the **security-hardened foundation** phase of the project. Currently implemented:

- ✅ **Banking-grade cryptographic security** (Ed25519 + Blake3)
- ✅ **Environment-based configuration** with secure salt management
- ✅ **Timestamp-based replay protection** for all operations
- ✅ **Cryptographic rate limiting** against timing attacks
- ✅ **PCI DSS compliant key management** with expiration
- ✅ **Comprehensive security testing** of all functionality
- 🔄 **Memory clearing** (planned for next iteration)

## Features

### Cryptographic Security
- **Blake3 hashing** for voter identity anonymization
- **Ed25519 signatures** for vote integrity and authentication
- **Secure random token generation** for voting credentials
- **Constant-time operations** to prevent timing attacks

### Voter Anonymization
- Deterministic but anonymous voter identification
- Unlinkable voting tokens
- Cryptographic separation of voter identity and vote content

### Election Management
- Basic election lifecycle (future, active, ended)
- Candidate management
- Vote timing validation

## Quick Start

### Prerequisites
- Rust 1.70+
- Cargo

### Build and Test

```bash
# Clone and build
git clone <repository>
cd vote
cargo build

# Run tests - start with simple test first
cargo test --test simple_test

# Run all tests
cargo test

# Run integration tests (comprehensive security tests)
cargo test --test integration_test

# Run with output to see detailed progress
cargo test --test integration_test -- --nocapture
```

### Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Generate secure salts for testing (in production use proper HSM/vault)
echo "CRYPTO_VOTER_SALT=$(openssl rand -base64 32)" >> .env
echo "CRYPTO_TOKEN_SALT=$(openssl rand -base64 32)" >> .env
```

### Check Code Quality

```bash
# Check for compilation errors
cargo check

# Run clippy for linting
cargo clippy

# Format code
cargo fmt
```

## Architecture

The system is designed with these core principles:

1. **Incremental Development**: Build and test each component before adding the next
2. **Security by Design**: Cryptographic operations are isolated and well-tested
3. **Admin-Proof Anonymity**: Even system administrators cannot link votes to voters
4. **Immutable Vote Records**: Votes cannot be changed once submitted

## Next Steps

The following components will be added incrementally:

1. **Configuration management** with environment variables
2. **Database layer** with separate databases for different concerns
3. **HTTP API** for election management and voting
4. **Authentication system** with Czech BankID integration
5. **Blind signature system** for advanced anonymity
6. **Audit logging** for security monitoring

## Testing

Run the comprehensive test suite:

```bash
# All tests
cargo test

# Just unit tests
cargo test --lib

# Just integration tests  
cargo test --test integration_test

# With detailed output
cargo test -- --nocapture

# Specific test
cargo test test_basic_crypto_operations
```

## Development

This project follows an incremental approach:

1. **Foundation** (current): Core types and crypto
2. **Configuration**: Environment-based config management
3. **Database**: Multi-database architecture for security
4. **API**: REST API for voting operations
5. **Authentication**: Czech BankID integration
6. **Advanced Features**: Blind signatures, audit trails

Each phase is fully tested before moving to the next.

## Security Notes

- All cryptographic operations use well-established libraries (Blake3, Ed25519)
- Voter anonymization is irreversible but deterministic
- Private keys and salts must be properly configured in production
- Timing attacks are mitigated through constant-time operations

## License

MIT OR Apache-2.0