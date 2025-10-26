# pp_clsag_core Library Explainer

## Overview

The `pp_clsag_core` library is a high-performance cryptographic library implemented in Rust with Python bindings. It provides essential cryptographic primitives for building privacy-preserving voting and reputation systems, with a focus on CLSAG (Concise Linkable Spontaneous Anonymous Group) ring signatures.

## Core Components

### 1. CLSAG Ring Signatures

**Purpose**: CLSAG provides efficient ring signatures with linkability properties, enabling anonymous authentication while preventing double-spending or double-voting.

**Key Features**:
- **Anonymity**: Signatures don't reveal which member of the ring created them
- **Linkability**: Signatures from the same signer can be linked together
- **Efficiency**: More efficient than traditional LSAG signatures
- **Spontaneous**: No trusted setup required

**Implementation Details**:
```rust
pub struct CLSAGSignature {
    pub key_image: [u8; 32],     // Links signatures from same signer
    pub responses: Vec<[u8; 32]>, // Response values for each ring member
    pub c1: [u8; 32],            // Challenge value
}
```

**How it works**:
1. **Ring Formation**: Public keys are canonicalized (sorted lexicographically)
2. **Key Image Computation**: `I = H(context) * secret_key` where `H` is hash-to-group
3. **Signature Generation**: Uses Fiat-Shamir transform with Merlin transcripts
4. **Verification**: Checks that the signature is valid for the ring without revealing the signer

**Use Cases**:
- Anonymous voting systems
- Privacy-preserving reputation systems
- Anonymous authentication
- Double-spending prevention

### 2. Blind RSA Signatures

**Purpose**: Enables anonymous authentication where the server can sign messages without knowing what it's signing.

**Key Features**:
- **Blinding**: Client blinds the message before sending to server
- **Unlinkability**: Server cannot link requests to responses
- **Unforgeability**: Only the server can create valid signatures
- **Verifiability**: Anyone can verify signatures with the public key

**Implementation Details**:
```rust
pub struct BlindRsaKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub bits: usize,
}

pub struct BlindedMessage {
    pub blinded_message: Vec<u8>,
    pub blinding_factor: BigUint,
}
```

**How it works**:
1. **Blinding**: Client computes `m' = m * r^e mod n` where `r` is random
2. **Signing**: Server signs `m'` to get `s' = (m')^d mod n`
3. **Unblinding**: Client computes `s = s' * r^(-1) mod n`
4. **Verification**: Standard RSA signature verification

**Use Cases**:
- Anonymous authentication tokens
- Privacy-preserving credential systems
- Anonymous access control

### 3. Pedersen Commitments

**Purpose**: Provides hiding and binding commitments to values, enabling zero-knowledge proofs and verifiable secret sharing.

**Key Features**:
- **Hiding**: Commitment doesn't reveal the committed value
- **Binding**: Cannot change the committed value after commitment
- **Additive Homomorphism**: Commitments can be combined
- **Verifiable**: Anyone can verify commitments

**Implementation Details**:
```rust
pub struct PedersenCommitment {
    pub commitment: [u8; 32],      // The commitment point
    pub value: i64,                // The committed value
    pub blinding_factor: [u8; 32], // Random blinding factor
}
```

**How it works**:
1. **Commitment**: `C = G * value + H * blinding_factor` where `G`, `H` are generators
2. **Verification**: Check that `C = G * value + H * blinding_factor`
3. **Context Binding**: Uses domain separation for different contexts

**Use Cases**:
- Verifiable voting systems
- Zero-knowledge proofs
- Secret sharing schemes
- Reputation systems

### 4. Schnorr Signatures

**Purpose**: Simple digital signatures for testing and basic authentication.

**Key Features**:
- **Simplicity**: Straightforward signature scheme
- **Efficiency**: Fast signing and verification
- **Security**: Based on discrete logarithm problem

**Implementation Details**:
```rust
// Returns (R_point, s_scalar)
pub fn sign_schnorr(message: &[u8], secret_key: &[u8; 32]) -> ([u8; 32], [u8; 32])
```

**How it works**:
1. **Signing**: `R = r * G`, `s = r + H(R||P||m) * secret_key`
2. **Verification**: Check `s * G = R + H(R||P||m) * P`

**Use Cases**:
- Basic authentication
- Testing cryptographic primitives
- Simple message signing

### 5. Key Derivation and Management

**Purpose**: Secure key generation and derivation from seeds.

**Key Features**:
- **HKDF**: Uses HKDF-SHA512 for key derivation
- **Deterministic**: Same seed always produces same keys
- **Secure**: Cryptographically secure random generation

**Implementation Details**:
```rust
pub fn keygen_from_seed(seed: &[u8; 32], digest: &[u8]) -> ([u8; 32], [u8; 32])
pub fn derive_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 32])
```

**How it works**:
1. **Seed Generation**: Cryptographically secure random 32-byte seed
2. **Key Derivation**: `HKDF(seed, digest, 32)` produces secret key
3. **Public Key**: `P = secret_key * G` where `G` is generator

**Use Cases**:
- Hierarchical key derivation
- Deterministic key generation
- Seed-based authentication

## Cryptographic Primitives

### Hash-to-Group Function

**Purpose**: Maps arbitrary bytes to points on the Ristretto group.

**Implementation**:
```rust
pub fn hash_to_ristretto(input: &[u8]) -> RistrettoPoint
```

**How it works**:
1. Hash input with SHA-512
2. Map hash output to RistrettoPoint
3. Ensures uniform distribution over the group

### Canonical Message Format

**Purpose**: Standardized message format for voting and reputation systems.

**Format**:
```
submission_id | genre | vote_type | epoch | nonce
```

**Benefits**:
- Prevents message malleability
- Enables temporal ordering
- Ensures uniqueness

### Key Image Computation

**Purpose**: Enables linkability in ring signatures.

**Implementation**:
```rust
pub fn key_image(secret_key: &[u8; 32], public_key: &[u8; 32], context: &[u8]) -> [u8; 32]
```

**How it works**:
1. Compute `H(context)` as a RistrettoPoint
2. Compute `I = H(context) * secret_key`
3. Return the compressed point

## Security Properties

### CLSAG Security

1. **Anonymity**: Signatures don't reveal the signer's identity
2. **Linkability**: Signatures from the same signer can be linked
3. **Unforgeability**: Cannot forge signatures without secret key
4. **Non-malleability**: Cannot modify signatures to create new valid ones

### Blind RSA Security

1. **Blinding**: Server cannot see the original message
2. **Unlinkability**: Server cannot link requests to responses
3. **Unforgeability**: Only server can create valid signatures
4. **Verifiability**: Anyone can verify signatures

### Pedersen Commitment Security

1. **Hiding**: Commitment doesn't reveal the value
2. **Binding**: Cannot change the committed value
3. **Zero-knowledge**: No information about the value is leaked

## Performance Characteristics

### CLSAG Performance

- **Signing**: O(n) where n is ring size
- **Verification**: O(n) where n is ring size
- **Memory**: O(n) for storing ring and responses
- **Typical Performance**: ~2-5ms for ring size 10

### Blind RSA Performance

- **Key Generation**: O(k³) where k is key size
- **Blinding**: O(k²) operations
- **Signing**: O(k²) operations
- **Verification**: O(k²) operations
- **Typical Performance**: ~10-50ms for 2048-bit keys

### Pedersen Commitment Performance

- **Commitment**: O(1) point operations
- **Verification**: O(1) point operations
- **Typical Performance**: ~0.1-0.5ms per operation

## Usage Patterns

### Anonymous Voting System

```python
# 1. Generate voter keypairs
voter_keys = []
for i in range(num_voters):
    seed = generate_seed()
    sk, pk = derive_keypair(seed)
    voter_keys.append((sk, pk))

# 2. Create canonical message
message = canonical_message(submission_id, genre, vote_type, epoch, nonce)

# 3. Create ring signature
ring = [pk for _, pk in voter_keys]
signature = clsag_sign(message, ring, voter_keys[voter_index][0], voter_index)

# 4. Verify signature
is_valid = clsag_verify(message, ring, signature)
```

### Anonymous Authentication

```python
# 1. Server creates keypair
server_keypair = BlindRsaKeyPair(2048)
public_key = server_keypair.export_public_key()

# 2. Client blinds message
blinded = BlindedMessage.blind(message, public_key)

# 3. Server signs blinded message
blind_signature = server_keypair.sign_blinded_message(blinded.get_blinded_message())

# 4. Client unblinds signature
unblinded_signature = blinded.unblind(blind_signature, public_key)

# 5. Verify signature
is_valid = verify_blind_signature(message, unblinded_signature, public_key)
```

### Reputation Commitments

```python
# 1. Create commitment to reputation score
commitment = pedersen_commit(reputation_score, b"reputation_context")

# 2. Verify commitment
is_valid = pedersen_verify(
    commitment.commitment, 
    commitment.value, 
    commitment.blinding_factor, 
    b"reputation_context"
)
```

## Error Handling

The library provides comprehensive error handling:

1. **Invalid Input**: Returns appropriate error messages for invalid inputs
2. **Cryptographic Failures**: Handles signature verification failures gracefully
3. **Memory Management**: Proper cleanup of sensitive data
4. **Type Safety**: Rust's type system prevents many common errors

## Testing and Verification

The library includes extensive tests:

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test complete workflows
3. **Property Tests**: Test cryptographic properties
4. **Performance Tests**: Benchmark operations

## Dependencies

### Rust Dependencies

- `curve25519-dalek`: Ristretto point arithmetic
- `rsa`: RSA operations
- `num-bigint`: Big integer arithmetic
- `merlin`: Fiat-Shamir transcripts
- `pyo3`: Python bindings
- `rand`: Random number generation
- `sha2`: SHA-256/512 hashing
- `hkdf`: Key derivation

### Python Dependencies

- `pp_clsag_core`: The compiled Rust library
- Standard library modules for testing and examples

## Future Enhancements

1. **Threshold Signatures**: Multi-party signature schemes
2. **Zero-Knowledge Proofs**: Range proofs and set membership
3. **Advanced Ring Signatures**: Linkable ring signatures with additional properties
4. **Performance Optimizations**: SIMD operations and parallel processing
5. **Additional Curves**: Support for other elliptic curves

## Conclusion

The `pp_clsag_core` library provides a solid foundation for building privacy-preserving systems. Its focus on CLSAG ring signatures, combined with blind RSA and Pedersen commitments, enables the construction of anonymous voting and reputation systems with strong security guarantees and good performance characteristics.

The Rust implementation ensures memory safety and performance, while the Python bindings make it accessible for rapid prototyping and integration into existing systems.
