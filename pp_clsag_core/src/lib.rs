// src/lib.rs
use hkdf::Hkdf;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::convert::TryInto;
use std::fmt;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use merlin::Transcript;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Signer, Verifier, SignatureEncoding};
use num_bigint::BigUint;

/// Secure memory management utilities
pub struct SecureMemory {
    data: Vec<u8>,
}

impl SecureMemory {
    pub fn new(size: usize) -> Self {
        SecureMemory {
            data: vec![0u8; size],
        }
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Securely zero out memory
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}

/// Memory pool for efficient allocation of cryptographic objects
pub struct CryptoMemoryPool {
    scalar_pool: Vec<Scalar>,
    point_pool: Vec<RistrettoPoint>,
    max_pool_size: usize,
}

impl CryptoMemoryPool {
    pub fn new(max_pool_size: usize) -> Self {
        CryptoMemoryPool {
            scalar_pool: Vec::with_capacity(max_pool_size),
            point_pool: Vec::with_capacity(max_pool_size),
            max_pool_size,
        }
    }
    
    pub fn get_scalar(&mut self) -> Scalar {
        self.scalar_pool.pop().unwrap_or(Scalar::ZERO)
    }
    
    pub fn return_scalar(&mut self, scalar: Scalar) {
        if self.scalar_pool.len() < self.max_pool_size {
            self.scalar_pool.push(scalar);
        }
    }
    
    pub fn get_point(&mut self) -> Option<RistrettoPoint> {
        self.point_pool.pop()
    }
    
    pub fn return_point(&mut self, point: RistrettoPoint) {
        if self.point_pool.len() < self.max_pool_size {
            self.point_pool.push(point);
        }
    }
    
    pub fn clear(&mut self) {
        // Securely clear all pooled objects
        for scalar in &mut self.scalar_pool {
            *scalar = Scalar::ZERO;
        }
        self.scalar_pool.clear();
        self.point_pool.clear();
    }
}

/// Memory-efficient batch operations
#[pyfunction]
fn clsag_verify_batch(messages: Vec<Vec<u8>>, ring_pubkeys: Vec<Vec<u8>>, 
                     signatures: Vec<CLSAGSignature>) -> PyResult<Vec<bool>> {
    if messages.len() != signatures.len() {
        return Err(PPCLSAGError::InvalidMessage(
            "Messages and signatures must have the same length".to_string()
        ).into());
    }
    
    // Pre-canonicalize the ring once
    let ring = canonicalize_ring(ring_pubkeys)?;
    
    // Pre-convert ring to RistrettoPoints to avoid repeated conversions
    let ring_points: Result<Vec<RistrettoPoint>, _> = ring.iter()
        .map(|pk_bytes| {
            CompressedRistretto::from_slice(pk_bytes)
                .map_err(|_| PPCLSAGError::InvalidKeyFormat("Invalid public key format".to_string()))?
                .decompress()
                .ok_or_else(|| PPCLSAGError::InvalidKeyFormat("Failed to decompress public key".to_string()))
        })
        .collect();
    let ring_points = ring_points?;
    
    let mut results = Vec::with_capacity(messages.len());
    
    for (message, signature) in messages.iter().zip(signatures.iter()) {
        let is_valid = clsag_verify_single(message, &ring, &ring_points, signature)?;
        results.push(is_valid);
    }
    
    Ok(results)
}

/// Internal function for single CLSAG verification with pre-converted ring points
fn clsag_verify_single(message: &[u8], ring: &[Vec<u8>], ring_points: &[RistrettoPoint], 
                      signature: &CLSAGSignature) -> PyResult<bool> {
    // Convert responses to Scalars
    let responses: Result<Vec<Scalar>, _> = signature.responses.iter()
        .map(|r_bytes| {
            let scalar_opt: Option<Scalar> = Scalar::from_canonical_bytes(r_bytes.as_slice().try_into().unwrap()).into();
            scalar_opt.ok_or_else(|| PPCLSAGError::InvalidSignature("Invalid response scalar".to_string()))
        })
        .collect();
    let responses = responses?;
    
    // Convert c1 to Scalar
    let c1_scalar_opt: Option<Scalar> = Scalar::from_canonical_bytes(signature.c1.clone().try_into().unwrap()).into();
    let c1_scalar = c1_scalar_opt.ok_or_else(|| PPCLSAGError::InvalidSignature("Invalid c1 scalar".to_string()))?;
    
    // Convert key image to RistrettoPoint
    let key_image_point = CompressedRistretto::from_slice(&signature.key_image)
        .map_err(|_| PPCLSAGError::InvalidSignature("Invalid key image format".to_string()))?
        .decompress()
        .ok_or_else(|| PPCLSAGError::InvalidSignature("Failed to decompress key image".to_string()))?;
    
    // Initialize transcript
    let mut transcript = Transcript::new(b"clsag");
    transcript.append_message(b"ring", &ring.iter().flatten().cloned().collect::<Vec<u8>>());
    transcript.append_message(b"key_image", &signature.key_image);
    transcript.append_message(b"message", message);
    
    // Verify each response
    let mut c_scalar = c1_scalar;
    for i in 0..ring.len() {
        let r_i = responses[i];
        let pk_i = &ring_points[i];
        
        // Compute left side of verification equation: L_i = r_i * G + c_i * P_i
        let r_i_g = &r_i * &RISTRETTO_BASEPOINT_POINT;
        let c_i_pk_i = &c_scalar * pk_i;
        let l_i = r_i_g + c_i_pk_i;
        
        // Compute right side of verification equation: R_i = r_i * H(P_i) + c_i * I
        let h_i = hash_to_ristretto(&ring[i]);
        let r_i_h_i = &r_i * &h_i;
        let c_i_key_image = &c_scalar * &key_image_point;
        let r_i = r_i_h_i + c_i_key_image;
        
        // Update transcript with verification points
        transcript.append_message(b"L", &l_i.compress().to_bytes());
        transcript.append_message(b"R", &r_i.compress().to_bytes());
        
        // Generate next challenge
        let mut challenge_bytes = [0u8; 32];
        transcript.challenge_bytes(b"c", &mut challenge_bytes);
        c_scalar = Scalar::from_bytes_mod_order(challenge_bytes);
    }
    
    // Check if final challenge matches c1
    Ok(c_scalar == c1_scalar)
}

/// Custom error types for better error handling
#[derive(Debug, Clone)]
pub enum PPCLSAGError {
    InvalidKeySize(String),
    InvalidKeyFormat(String),
    InvalidSignature(String),
    InvalidRingSize(String),
    InvalidMessage(String),
    CryptographicError(String),
    MemoryError(String),
    PerformanceError(String),
}

impl std::fmt::Display for PPCLSAGError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PPCLSAGError::InvalidKeySize(msg) => write!(f, "Invalid key size: {}", msg),
            PPCLSAGError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
            PPCLSAGError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            PPCLSAGError::InvalidRingSize(msg) => write!(f, "Invalid ring size: {}", msg),
            PPCLSAGError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            PPCLSAGError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            PPCLSAGError::MemoryError(msg) => write!(f, "Memory error: {}", msg),
            PPCLSAGError::PerformanceError(msg) => write!(f, "Performance error: {}", msg),
        }
    }
}

impl std::error::Error for PPCLSAGError {}

impl From<PPCLSAGError> for PyErr {
    fn from(err: PPCLSAGError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}

/// Helper function to convert generic errors to specific PPCLSAG errors
fn to_ppclsag_error<T: std::fmt::Display>(err: T, error_type: PPCLSAGError) -> PyErr {
    PyValueError::new_err(format!("{}: {}", error_type, err))
}

/// Performance monitoring and optimization utilities
#[pyclass]
pub struct PerformanceMonitor {
    #[pyo3(get)]
    pub operation_count: u64,
    #[pyo3(get)]
    pub total_time_ms: f64,
    #[pyo3(get)]
    pub average_time_ms: f64,
}

#[pymethods]
impl PerformanceMonitor {
    #[new]
    pub fn new() -> Self {
        PerformanceMonitor {
            operation_count: 0,
            total_time_ms: 0.0,
            average_time_ms: 0.0,
        }
    }
    
    pub fn record_operation(&mut self, time_ms: f64) {
        self.operation_count += 1;
        self.total_time_ms += time_ms;
        self.average_time_ms = self.total_time_ms / self.operation_count as f64;
    }
    
    pub fn reset(&mut self) {
        self.operation_count = 0;
        self.total_time_ms = 0.0;
        self.average_time_ms = 0.0;
    }
}

/// Optimized batch operations for large rings
#[pyfunction]
fn clsag_sign_batch(messages: Vec<Vec<u8>>, ring_pubkeys: Vec<Vec<u8>>, 
                   signer_sks: Vec<Vec<u8>>, signer_indices: Vec<usize>) -> PyResult<Vec<CLSAGSignature>> {
    if messages.len() != signer_sks.len() || messages.len() != signer_indices.len() {
        return Err(PPCLSAGError::InvalidMessage(
            "All input vectors must have the same length".to_string()
        ).into());
    }
    
    // Pre-canonicalize the ring once
    let ring = canonicalize_ring(ring_pubkeys)?;
    
    // Pre-compute common values
    let mut signatures = Vec::with_capacity(messages.len());
    
    for (i, ((message, signer_sk), signer_index)) in messages.iter()
        .zip(signer_sks.iter())
        .zip(signer_indices.iter())
        .enumerate() {
        
        // Validate inputs
        if signer_sk.len() != 32 {
            return Err(PPCLSAGError::InvalidKeyFormat(
                format!("Secret key at index {} must be 32 bytes, got {} bytes", i, signer_sk.len())
            ).into());
        }
        if *signer_index >= ring.len() {
            return Err(PPCLSAGError::InvalidRingSize(
                format!("Signer index {} at position {} out of bounds for ring of size {}", signer_index, i, ring.len())
            ).into());
        }
        
        // Create signature using the pre-canonicalized ring
        let signature = clsag_sign_single(message, &ring, signer_sk, *signer_index)?;
        signatures.push(signature);
    }
    
    Ok(signatures)
}

/// Internal function for single CLSAG signature with pre-canonicalized ring
fn clsag_sign_single(message: &[u8], ring: &[Vec<u8>], signer_sk: &[u8], _signer_index: usize) -> PyResult<CLSAGSignature> {
    // Convert secret key to Scalar
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(signer_sk.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PPCLSAGError::InvalidKeyFormat("Invalid secret key".to_string()))?;
    
    // Find the signer's public key in the canonicalized ring
    let signer_pk = {
        let pk_point: RistrettoPoint = &sk * &RISTRETTO_BASEPOINT_POINT;
        pk_point.compress().to_bytes().to_vec()
    };
    
    let new_signer_index = ring.iter().position(|pk| pk == &signer_pk)
        .ok_or_else(|| PPCLSAGError::InvalidKeyFormat("Signer's public key not found in ring".to_string()))?;
    
    // Compute key image
    let key_image_bytes = key_image(signer_sk, &signer_pk, b"clsag_context")?;
    let key_image_point = CompressedRistretto::from_slice(&key_image_bytes)
        .map_err(|_| PPCLSAGError::CryptographicError("Invalid key image".to_string()))?
        .decompress()
        .ok_or_else(|| PPCLSAGError::CryptographicError("Failed to decompress key image".to_string()))?;
    
    // Convert ring to RistrettoPoints
    let ring_points: Result<Vec<RistrettoPoint>, _> = ring.iter()
        .map(|pk_bytes| {
            CompressedRistretto::from_slice(pk_bytes)
                .map_err(|_| PPCLSAGError::InvalidKeyFormat("Invalid public key format".to_string()))?
                .decompress()
                .ok_or_else(|| PPCLSAGError::InvalidKeyFormat("Failed to decompress public key".to_string()))
        })
        .collect();
    let ring_points = ring_points?;
    
    // Initialize transcript
    let mut transcript = Transcript::new(b"clsag");
    transcript.append_message(b"ring", &ring.iter().flatten().cloned().collect::<Vec<u8>>());
    transcript.append_message(b"key_image", &key_image_bytes);
    transcript.append_message(b"message", message);
    
    // Generate random responses for non-signer positions
    let mut responses = vec![Scalar::ZERO; ring.len()];
    let mut rng = OsRng;
    
    for i in 0..ring.len() {
        if i != new_signer_index {
            let mut r_bytes = [0u8; 32];
            rng.fill_bytes(&mut r_bytes);
            responses[i] = Scalar::from_bytes_mod_order(r_bytes);
        }
    }
    
    // Compute challenge
    let mut c_scalar = Scalar::ZERO;
    for i in 0..ring.len() {
        if i == new_signer_index {
            continue;
        }
        
        let r_i = responses[i];
        let pk_i = &ring_points[i];
        
        // Compute left side of verification equation
        let r_i_g = &r_i * &RISTRETTO_BASEPOINT_POINT;
        let c_i_pk_i = &c_scalar * pk_i;
        let l_i = r_i_g + c_i_pk_i;
        
        // Compute right side of verification equation
        let h_i = hash_to_ristretto(&ring[i]);
        let r_i_h_i = &r_i * &h_i;
        let c_i_key_image = &c_scalar * &key_image_point;
        let r_i = r_i_h_i + c_i_key_image;
        
        // Update challenge
        transcript.append_message(b"L", &l_i.compress().to_bytes());
        transcript.append_message(b"R", &r_i.compress().to_bytes());
        
        let mut challenge_bytes = [0u8; 32];
        transcript.challenge_bytes(b"c", &mut challenge_bytes);
        c_scalar = Scalar::from_bytes_mod_order(challenge_bytes);
    }
    
    // Compute the signer's response
    let r_signer = responses[new_signer_index];
    let pk_signer = &ring_points[new_signer_index];
    
    let r_signer_g = &r_signer * &RISTRETTO_BASEPOINT_POINT;
    let c_signer_pk_signer = &c_scalar * pk_signer;
    let l_signer = r_signer_g + c_signer_pk_signer;
    
    let h_signer = hash_to_ristretto(&ring[new_signer_index]);
    let r_signer_h_signer = &r_signer * &h_signer;
    let c_signer_key_image = &c_scalar * &key_image_point;
    let r_signer = r_signer_h_signer + c_signer_key_image;
    
    transcript.append_message(b"L", &l_signer.compress().to_bytes());
    transcript.append_message(b"R", &r_signer.compress().to_bytes());
    
    let mut final_challenge_bytes = [0u8; 32];
    transcript.challenge_bytes(b"c", &mut final_challenge_bytes);
    let final_c = Scalar::from_bytes_mod_order(final_challenge_bytes);
    
    // Compute the actual response for the signer
    responses[new_signer_index] = sk + final_c * sk;
    
    // Convert responses to bytes
    let response_bytes: Vec<Vec<u8>> = responses.iter()
        .map(|r| r.to_bytes().to_vec())
        .collect();
    
    Ok(CLSAGSignature {
        key_image: key_image_bytes,
        c1: final_c.to_bytes().to_vec(),
        responses: response_bytes,
    })
}

/// Represents a blind-RSA key pair for the server
#[pyclass]
pub struct BlindRsaKeyPair {
    #[pyo3(get)]
    pub bits: usize,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

/// Represents a blinded message from the client
#[pyclass]
pub struct BlindedMessage {
    blinded_message: Vec<u8>,
    blinding_factor: BigUint,
}

/// Represents a blind signature from the server
#[pyclass]
pub struct BlindSignature {
    signature: Vec<u8>,
}

#[pymethods]
impl BlindRsaKeyPair {
    #[new]
    pub fn new(bits: usize) -> PyResult<Self> {
        // Validate key size
        if bits < 512 || bits > 8192 {
            return Err(PPCLSAGError::InvalidKeySize(
                format!("Key size {} bits is not supported. Must be between 512 and 8192 bits", bits)
            ).into());
        }
        
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| PyValueError::new_err(format!("Failed to generate RSA key: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);
        
        Ok(BlindRsaKeyPair {
            bits,
            private_key,
            public_key,
        })
    }
    
    /// Export the public key for distribution to clients
    pub fn export_public_key(&self) -> Vec<u8> {
        let n_bytes = self.public_key.n().to_bytes_be();
        let e_bytes = self.public_key.e().to_bytes_be();
        
        // Format: [n_len(4 bytes)][n_bytes][e_bytes]
        let mut result = Vec::new();
        let n_len = n_bytes.len() as u32;
        result.extend_from_slice(&n_len.to_be_bytes());
        result.extend_from_slice(&n_bytes);
        result.extend_from_slice(&e_bytes);
        
        result
    }
    
    /// Sign a blinded message using the server's private key
    pub fn sign_blinded_message(&self, blinded_message: &[u8]) -> PyResult<BlindSignature> {
        let signing_key = SigningKey::<Sha512>::new_unprefixed(self.private_key.clone());
        
        let signature = signing_key.sign(blinded_message);
        
        Ok(BlindSignature {
            signature: signature.to_vec(),
        })
    }
}

#[pymethods]
impl BlindedMessage {
    /// Create a new blinded message from a message and a public key
    #[staticmethod]
    pub fn blind(message: &[u8], public_key_bytes: &[u8]) -> PyResult<Self> {
        // Parse the public key
        if public_key_bytes.len() < 4 {
            return Err(PyValueError::new_err("Invalid public key format"));
        }
        
        let mut n_len_bytes = [0u8; 4];
        n_len_bytes.copy_from_slice(&public_key_bytes[0..4]);
        let n_len = u32::from_be_bytes(n_len_bytes) as usize;
        
        if public_key_bytes.len() < 4 + n_len {
            return Err(PyValueError::new_err("Invalid public key format"));
        }
        
        let n_bytes = &public_key_bytes[4..4+n_len];
        let e_bytes = &public_key_bytes[4+n_len..];
        
        let n = BigUint::from_bytes_be(n_bytes);
        let e = BigUint::from_bytes_be(e_bytes);
        
        // Generate a random blinding factor r such that gcd(r, n) = 1
        let mut rng = OsRng;
        let mut r = BigUint::from(0u32);
        
        // Simple approach: keep generating until we find a suitable r
        // In practice, we should use a more sophisticated approach
        while r == BigUint::from(0u32) || r >= n {
            let mut r_bytes = vec![0u8; n_bytes.len()];
            rng.fill_bytes(&mut r_bytes);
            r = BigUint::from_bytes_be(&r_bytes);
        }
        
        // Hash the message (using SHA-512)
        let mut hasher = Sha512::new();
        hasher.update(message);
        let hashed_message = hasher.finalize();
        let m = BigUint::from_bytes_be(&hashed_message);
        
        // Blind the message: m' = m * r^e mod n
        let r_e = r.modpow(&e, &n);
        let blinded_message = (m * r_e) % &n;
        
        Ok(BlindedMessage {
            blinded_message: blinded_message.to_bytes_be(),
            blinding_factor: r,
        })
    }
    
    /// Get the blinded message to send to the server
    pub fn get_blinded_message(&self) -> Vec<u8> {
        self.blinded_message.clone()
    }
    
    /// Unblind a signature received from the server
    pub fn unblind(&self, blind_signature: &BlindSignature, public_key_bytes: &[u8]) -> PyResult<Vec<u8>> {
        // Parse the public key
        if public_key_bytes.len() < 4 {
            return Err(PyValueError::new_err("Invalid public key format"));
        }
        
        let mut n_len_bytes = [0u8; 4];
        n_len_bytes.copy_from_slice(&public_key_bytes[0..4]);
        let n_len = u32::from_be_bytes(n_len_bytes) as usize;
        
        if public_key_bytes.len() < 4 + n_len {
            return Err(PyValueError::new_err("Invalid public key format"));
        }
        
        let n_bytes = &public_key_bytes[4..4+n_len];
        let n = BigUint::from_bytes_be(n_bytes);
        
        // Convert the blinded signature to BigUint
        let s_prime = BigUint::from_bytes_be(&blind_signature.signature);
        
        // Compute r^-1 mod n
        let r_inv = self.blinding_factor.clone()
            .modinv(&n)
            .ok_or_else(|| PyValueError::new_err("Failed to compute modular inverse"))?;
        
        // Unblind the signature: s = s' * r^-1 mod n
        let s = (s_prime * r_inv) % &n;
        
        Ok(s.to_bytes_be())
    }
}

#[pymethods]
impl BlindSignature {
    #[new]
    pub fn new(signature: Vec<u8>) -> Self {
        BlindSignature { signature }
    }
    
    pub fn get_signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

/// Verify a blind signature against a message and public key
#[pyfunction]
pub fn verify_blind_signature(message: &[u8], signature: &[u8], public_key_bytes: &[u8]) -> PyResult<bool> {
    // Parse the public key
    if public_key_bytes.len() < 4 {
        return Err(PyValueError::new_err("Invalid public key format"));
    }
    
    let mut n_len_bytes = [0u8; 4];
    n_len_bytes.copy_from_slice(&public_key_bytes[0..4]);
    let n_len = u32::from_be_bytes(n_len_bytes) as usize;
    
    if public_key_bytes.len() < 4 + n_len {
        return Err(PyValueError::new_err("Invalid public key format"));
    }
    
    let n_bytes = &public_key_bytes[4..4+n_len];
    let e_bytes = &public_key_bytes[4+n_len..];
    
    let n = BigUint::from_bytes_be(n_bytes);
    let e = BigUint::from_bytes_be(e_bytes);
    
    // Create a public key from the components
    let n_rsa = rsa::BigUint::from_bytes_be(&n.to_bytes_be());
    let e_rsa = rsa::BigUint::from_bytes_be(&e.to_bytes_be());
    let public_key = RsaPublicKey::new(n_rsa, e_rsa)
        .map_err(|e| PyValueError::new_err(format!("Failed to create RSA public key: {}", e)))?;
    
    // Hash the message
    let mut hasher = Sha512::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();
    
    // Create a verifying key
    let verifying_key = VerifyingKey::<Sha512>::new_unprefixed(public_key);
    
    // Verify the signature
    let signature_obj = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|e| PyValueError::new_err(format!("Invalid signature format: {}", e)))?;
    
    match verifying_key.verify(hashed_message.as_slice(), &signature_obj) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    // Blind RSA tests
    #[test]
    fn test_blind_rsa_end_to_end() {
        // Create a server key pair (using a smaller key size for faster tests)
        let server_keypair = BlindRsaKeyPair::new(1024).unwrap();
        let public_key = server_keypair.export_public_key();
        
        // Client: Create a message and blind it
        let message = b"This is a test message";
        let blinded_message = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data = blinded_message.get_blinded_message();
        
        // Server: Sign the blinded message
        let blind_signature = server_keypair.sign_blinded_message(&blinded_data).unwrap();
        
        // Client: Unblind the signature
        let unblinded_signature = blinded_message.unblind(&blind_signature, &public_key).unwrap();
        
        // Verify the signature
        let is_valid = verify_blind_signature(message, &unblinded_signature, &public_key).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_blind_rsa_unlinkability() {
        // Create a server key pair
        let server_keypair = BlindRsaKeyPair::new(1024).unwrap();
        let public_key = server_keypair.export_public_key();
        
        // Client: Create two identical messages and blind them differently
        let message = b"This is a test message";
        let blinded_message1 = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data1 = blinded_message1.get_blinded_message();
        
        let blinded_message2 = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data2 = blinded_message2.get_blinded_message();
        
        // The blinded messages should be different (unlinkability)
        assert_ne!(blinded_data1, blinded_data2);
        
        // Server: Sign both blinded messages
        let blind_signature1 = server_keypair.sign_blinded_message(&blinded_data1).unwrap();
        let blind_signature2 = server_keypair.sign_blinded_message(&blinded_data2).unwrap();
        
        // Client: Unblind both signatures
        let unblinded_signature1 = blinded_message1.unblind(&blind_signature1, &public_key).unwrap();
        let unblinded_signature2 = blinded_message2.unblind(&blind_signature2, &public_key).unwrap();
        
        // The unblinded signatures should be different
        assert_ne!(unblinded_signature1, unblinded_signature2);
        
        // But both should verify against the original message
        let is_valid1 = verify_blind_signature(message, &unblinded_signature1, &public_key).unwrap();
        let is_valid2 = verify_blind_signature(message, &unblinded_signature2, &public_key).unwrap();
        
        assert!(is_valid1);
        assert!(is_valid2);
    }
    
    #[test]
    fn test_blind_rsa_unforgeability() {
        // Create a server key pair
        let server_keypair = BlindRsaKeyPair::new(1024).unwrap();
        let public_key = server_keypair.export_public_key();
        
        // Client: Create a message and blind it
        let message = b"This is a test message";
        let blinded_message = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data = blinded_message.get_blinded_message();
        
        // Server: Sign the blinded message
        let blind_signature = server_keypair.sign_blinded_message(&blinded_data).unwrap();
        
        // Client: Unblind the signature
        let unblinded_signature = blinded_message.unblind(&blind_signature, &public_key).unwrap();
        
        // Try to verify with a different message
        let different_message = b"This is a different message";
        let is_valid = verify_blind_signature(different_message, &unblinded_signature, &public_key).unwrap();
        
        // Should fail verification
        assert!(!is_valid);
    }
    
    // Property-based tests using proptest
    #[cfg(feature = "proptest")]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;
        
        proptest! {
            #[test]
            fn test_clsag_sign_verify_property(
                message in prop::collection::vec(any::<u8>(), 1..100),
                ring_size in 2..20usize,
                signer_index in 0..20usize
            ) {
                // Ensure signer_index is within bounds
                let signer_index = signer_index % ring_size;
                
                // Generate a ring of keypairs
                let mut ring = Vec::new();
                let mut secret_keys = Vec::new();
                
                for _ in 0..ring_size {
                    let seed = generate_seed().unwrap();
                    let (sk, pk) = derive_keypair(seed).unwrap();
                    secret_keys.push(sk);
                    ring.push(pk);
                }
                
                // Sign the message
                let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_index], signer_index).unwrap();
                
                // Verify the signature
                let is_valid = clsag_verify(&message, ring, &signature).unwrap();
                assert!(is_valid);
            }
            
            #[test]
            fn test_pedersen_commitment_property(
                value in 0..10000u64,
                context in prop::collection::vec(any::<u8>(), 0..50)
            ) {
                let commitment = pedersen_commit(value, &context).unwrap();
                let is_valid = pedersen_verify(
                    &commitment.commitment,
                    commitment.value,
                    &commitment.blinding_factor,
                    &context
                ).unwrap();
                assert!(is_valid);
                assert_eq!(commitment.value, value);
            }
            
            #[test]
            fn test_schnorr_sign_verify_property(
                message in prop::collection::vec(any::<u8>(), 1..100)
            ) {
                let seed = generate_seed().unwrap();
                let (sk, pk) = derive_keypair(seed).unwrap();
                
                let (r_bytes, s_bytes) = sign_schnorr(&message, &sk).unwrap();
                let is_valid = verify_schnorr(&message, &pk, &r_bytes, &s_bytes).unwrap();
                assert!(is_valid);
            }
            
            #[test]
            fn test_key_image_property(
                context in prop::collection::vec(any::<u8>(), 0..50)
            ) {
                let seed = generate_seed().unwrap();
                let (sk, pk) = derive_keypair(seed).unwrap();
                
                let key_img1 = key_image(&sk, &pk, &context).unwrap();
                let key_img2 = key_image(&sk, &pk, &context).unwrap();
                
                // Key image should be deterministic
                assert_eq!(key_img1, key_img2);
                assert_eq!(key_img1.len(), 32);
            }
            
            #[test]
            fn test_canonicalize_ring_property(
                ring_size in 2..50usize
            ) {
                let mut ring = Vec::new();
                
                for _ in 0..ring_size {
                    let seed = generate_seed().unwrap();
                    let (_, pk) = derive_keypair(seed).unwrap();
                    ring.push(pk);
                }
                
                let canonical_ring = canonicalize_ring(ring.clone()).unwrap();
                
                // Canonical ring should be sorted
                for i in 1..canonical_ring.len() {
                    assert!(canonical_ring[i-1] <= canonical_ring[i]);
                }
                
                // Canonical ring should have same length
                assert_eq!(canonical_ring.len(), ring.len());
            }
        }
    }
}

/// Derive sk scalar bytes and pk bytes from a user-local seed and credential digest D.
/// sk := HKDF(seed, D) -> 32 bytes -> Scalar(mod p)
/// pk := sk * B
#[pyfunction]
fn keygen_from_seed(seed: &[u8], d: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // HKDF-SHA512 with D as salt
    let hk = Hkdf::<Sha512>::new(Some(d), seed);
    let mut okm = [0u8; 32];
    hk.expand(b"PP-CLSAG-SK", &mut okm)
        .map_err(|_| PyValueError::new_err("hkdf expand failed"))?;

    let sk = Scalar::from_bytes_mod_order(okm);
    let pk_point: RistrettoPoint = &sk * &RISTRETTO_BASEPOINT_POINT;

    Ok((sk.to_bytes().to_vec(), pk_point.compress().to_bytes().to_vec()))
}

/// Hash-to-group for arbitrary bytes -> RistrettoPoint using SHA512 -> from_uniform_bytes
fn hash_to_ristretto(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(input);
    let out = h.finalize(); // 64 bytes
    let arr: [u8; 64] = out.as_slice().try_into().expect("Sha512 output size mismatch");
    RistrettoPoint::from_uniform_bytes(&arr)
}

/// Generate a random seed for key derivation
#[pyfunction]
fn generate_seed() -> PyResult<Vec<u8>> {
    let mut seed = vec![0u8; 32];
    OsRng.fill_bytes(&mut seed);
    Ok(seed)
}

/// Derive a keypair from a seed
#[pyfunction]
fn derive_keypair(seed: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Use an empty digest for the default case
    keygen_from_seed(&seed, b"")
}

/// Canonicalize a ring of public keys by sorting them lexicographically
#[pyfunction]
fn canonicalize_ring(pubkeys: Vec<Vec<u8>>) -> PyResult<Vec<Vec<u8>>> {
    let mut sorted_pubkeys = pubkeys;
    sorted_pubkeys.sort();
    Ok(sorted_pubkeys)
}

/// Create a canonical message format for voting
#[pyfunction]
fn canonical_message(submission_id: &str, genre: &str, vote_type: &str, epoch: u64, nonce: &str) -> PyResult<Vec<u8>> {
    let mut result = Vec::new();
    
    // Add submission_id with length prefix
    let id_bytes = submission_id.as_bytes();
    result.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(id_bytes);
    
    // Add genre with length prefix
    let genre_bytes = genre.as_bytes();
    result.extend_from_slice(&(genre_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(genre_bytes);
    
    // Add vote_type with length prefix
    let vote_type_bytes = vote_type.as_bytes();
    result.extend_from_slice(&(vote_type_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(vote_type_bytes);
    
    // Add epoch as 8 bytes
    result.extend_from_slice(&epoch.to_be_bytes());
    
    // Add nonce with length prefix
    let nonce_bytes = nonce.as_bytes();
    result.extend_from_slice(&(nonce_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(nonce_bytes);
    
    Ok(result)
}

/// Compute context-bound key image/tag: I = sk * Hp(pk || context)
#[pyfunction]
fn key_image(sk_bytes: &[u8], pk_bytes: &[u8], context: &[u8]) -> PyResult<Vec<u8>> {
    if sk_bytes.len() != 32 {
        return Err(PyValueError::new_err("sk must be 32 bytes"));
    }

    // Convert sk bytes -> Scalar (use from_canonical_bytes -> CtOption -> Option)
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(sk_bytes.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("invalid sk scalar"))?;

    // Compose pk || context
    let mut buf = Vec::with_capacity(pk_bytes.len() + context.len());
    buf.extend_from_slice(pk_bytes);
    buf.extend_from_slice(context);

    let hp = hash_to_ristretto(&buf);
    let key_image_point = &sk * &hp;
    Ok(key_image_point.compress().to_bytes().to_vec())
}

/// CLSAG Signature structure
#[pyclass]
#[derive(Clone)]
pub struct CLSAGSignature {
    #[pyo3(get)]
    pub key_image: Vec<u8>,
    pub c1: Vec<u8>,
    pub responses: Vec<Vec<u8>>,
}

#[pymethods]
impl CLSAGSignature {
    #[new]
    fn new(key_image: Vec<u8>, c1: Vec<u8>, responses: Vec<Vec<u8>>) -> Self {
        CLSAGSignature {
            key_image,
            c1,
            responses,
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("CLSAGSignature(key_image={:?}, responses={})", 
                  self.key_image, self.responses.len()))
    }
}

/// Sign a message using CLSAG (Concise Linkable Spontaneous Anonymous Group)
/// This is more efficient than LSAG with smaller signatures and faster verification
#[pyfunction]
fn clsag_sign(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, signer_sk: &[u8], signer_index: usize) -> PyResult<CLSAGSignature> {
    // Validate inputs with specific error types
    if ring_pubkeys.is_empty() {
        return Err(PPCLSAGError::InvalidRingSize("Ring cannot be empty".to_string()).into());
    }
    if ring_pubkeys.len() > 1000 {
        return Err(PPCLSAGError::PerformanceError(
            format!("Ring size {} is too large for optimal performance. Maximum recommended size is 1000", ring_pubkeys.len())
        ).into());
    }
    if signer_index >= ring_pubkeys.len() {
        return Err(PPCLSAGError::InvalidRingSize(
            format!("Signer index {} out of bounds for ring of size {}", signer_index, ring_pubkeys.len())
        ).into());
    }
    if signer_sk.len() != 32 {
        return Err(PPCLSAGError::InvalidKeyFormat(
            format!("Secret key must be 32 bytes, got {} bytes", signer_sk.len())
        ).into());
    }
    if message.is_empty() {
        return Err(PPCLSAGError::InvalidMessage("Message cannot be empty".to_string()).into());
    }

    // Canonicalize the ring
    let ring = canonicalize_ring(ring_pubkeys)?;
    
    // Find the new index of the signer after canonicalization
    let signer_pk = {
        let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(signer_sk.try_into().unwrap()).into();
        let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
        let pk_point = &sk * &RISTRETTO_BASEPOINT_POINT;
        pk_point.compress().to_bytes().to_vec()
    };
    
    let canonical_signer_index = match ring.iter().position(|pk| pk == &signer_pk) {
        Some(idx) => idx,
        None => return Err(PyValueError::new_err("Signer public key not found in canonicalized ring")),
    };

    // Convert public keys to RistrettoPoints
    let ring_points: Vec<RistrettoPoint> = ring.iter()
        .map(|pk| {
            let compressed = match CompressedRistretto::from_slice(pk) {
                Ok(c) => c,
                Err(_) => return Err(PyValueError::new_err("Invalid public key format")),
            };
            let point = compressed.decompress()
                .ok_or_else(|| PyValueError::new_err("Invalid public key in ring"))?;
            Ok(point)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Compute key image
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(signer_sk.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
    
    // Compute key image point: I = x * H_p(P)
    let mut pk_hash_input = Vec::new();
    pk_hash_input.extend_from_slice(&signer_pk);
    let h_point = hash_to_ristretto(&pk_hash_input);
    let key_image_point = &sk * &h_point;
    let key_image_bytes = key_image_point.compress().to_bytes().to_vec();

    // Initialize Merlin transcript for Fiat-Shamir
    let mut transcript = Transcript::new(b"proofpals:clsag");
    
    // Commit to the message
    transcript.append_message(b"message", message);
    
    // Commit to the ring
    for pk in &ring {
        transcript.append_message(b"pubkey", pk);
    }
    
    // Commit to the key image
    transcript.append_message(b"key_image", &key_image_bytes);

    // Generate random scalar
    let mut rng = OsRng;
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    let alpha = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
    
    // Compute commitment points
    let a_point = &alpha * &RISTRETTO_BASEPOINT_POINT;
    let b_point = &alpha * &h_point;
    
    // Commit the random points to the transcript
    transcript.append_message(b"a_point", &a_point.compress().to_bytes());
    transcript.append_message(b"b_point", &b_point.compress().to_bytes());
    
    // Generate challenge
    let mut c_scalar_bytes = [0u8; 32];
    transcript.challenge_bytes(b"c", &mut c_scalar_bytes);
    let mut c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);
    
    // Prepare responses vector
    let n = ring.len();
    let mut responses = Vec::with_capacity(n);
    
    // Compute responses for each ring member
    for i in 0..n {
        if i == canonical_signer_index {
            // For the real signer: r_i = alpha - c * sk
            let r_i = alpha - c_scalar * sk;
            responses.push(r_i.to_bytes().to_vec());
        } else {
            // For decoys: generate random response
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            let r_i = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
            responses.push(r_i.to_bytes().to_vec());
            
            // Update challenge for next iteration
            let r_i_g = &r_i * &RISTRETTO_BASEPOINT_POINT;
            let pk_i = &ring_points[i];
            let c_i_pk_i = &c_scalar * pk_i;
            let l_i = r_i_g + c_i_pk_i;
            
            // Compute right side of verification equation
            let h_i = hash_to_ristretto(&ring[i]);
            let r_i_h_i = &r_i * &h_i;
            let c_i_key_image = &c_scalar * &key_image_point;
            let r_i = r_i_h_i + c_i_key_image;
            
            // Update challenge
            transcript.append_message(b"L", &l_i.compress().to_bytes());
            transcript.append_message(b"R", &r_i.compress().to_bytes());
            
            // Generate next challenge
            transcript.challenge_bytes(b"c", &mut c_scalar_bytes);
            c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);
        }
    }
    
    // Return the signature
    Ok(CLSAGSignature {
        key_image: key_image_bytes,
        c1: c_scalar.to_bytes().to_vec(),
        responses,
    })
}

/// Verify a CLSAG signature
#[pyfunction]
fn clsag_verify(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, signature: &CLSAGSignature) -> PyResult<bool> {
    // Validate inputs with specific error types
    if ring_pubkeys.is_empty() {
        return Err(PPCLSAGError::InvalidRingSize("Ring cannot be empty".to_string()).into());
    }
    if ring_pubkeys.len() > 1000 {
        return Err(PPCLSAGError::PerformanceError(
            format!("Ring size {} is too large for optimal performance. Maximum recommended size is 1000", ring_pubkeys.len())
        ).into());
    }
    if signature.responses.len() != ring_pubkeys.len() {
        return Err(PPCLSAGError::InvalidSignature(
            format!("Signature response count {} doesn't match ring size {}", signature.responses.len(), ring_pubkeys.len())
        ).into());
    }
    if message.is_empty() {
        return Err(PPCLSAGError::InvalidMessage("Message cannot be empty".to_string()).into());
    }
    
    // Canonicalize the ring
    let ring = canonicalize_ring(ring_pubkeys)?;
    
    // Convert public keys to RistrettoPoints
    let ring_points: Vec<RistrettoPoint> = ring.iter()
        .map(|pk| {
            let compressed = match CompressedRistretto::from_slice(pk) {
                Ok(c) => c,
                Err(_) => return Err(PyValueError::new_err("Invalid public key format")),
            };
            compressed.decompress()
                .ok_or_else(|| PyValueError::new_err("Invalid public key in ring"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    
    // Decompress key image
    let compressed_key_image = match CompressedRistretto::from_slice(&signature.key_image) {
        Ok(c) => c,
        Err(_) => return Err(PyValueError::new_err("Invalid key image format")),
    };
    let key_image_point = compressed_key_image.decompress()
        .ok_or_else(|| PyValueError::new_err("Invalid key image"))?;
    
    // Initialize Merlin transcript for Fiat-Shamir
    let mut transcript = Transcript::new(b"proofpals:clsag");
    
    // Commit to the message
    transcript.append_message(b"message", message);
    
    // Commit to the ring
    for pk in &ring {
        transcript.append_message(b"pubkey", pk);
    }
    
    // Commit to the key image
    transcript.append_message(b"key_image", &signature.key_image);
    
    // Get initial challenge
    let mut c_scalar = match Scalar::from_canonical_bytes(signature.c1.clone().try_into().unwrap()).into() {
        Some(s) => s,
        None => return Err(PyValueError::new_err("Invalid challenge in signature")),
    };
    
    // Verify the signature
    let n = ring.len();
    
    for i in 0..n {
        // Get response scalar
        let r_i = match Scalar::from_canonical_bytes(signature.responses[i].clone().try_into().unwrap()).into() {
            Some(s) => s,
            None => return Err(PyValueError::new_err("Invalid response in signature")),
        };
        
        // Compute left side of verification equation: L_i = r_i * G + c_i * P_i
        let r_i_g = &r_i * &RISTRETTO_BASEPOINT_POINT;
        let pk_i = &ring_points[i];
        let c_i_pk_i = &c_scalar * pk_i;
        let l_i = r_i_g + c_i_pk_i;
        
        // Compute right side of verification equation: R_i = r_i * H(P_i) + c_i * I
        let h_i = hash_to_ristretto(&ring[i]);
        let r_i_h_i = &r_i * &h_i;
        let c_i_key_image = &c_scalar * &key_image_point;
        let r_i = r_i_h_i + c_i_key_image;
        
        // Update transcript with verification points
        transcript.append_message(b"L", &l_i.compress().to_bytes());
        transcript.append_message(b"R", &r_i.compress().to_bytes());
        
        // Generate next challenge
        let mut c_scalar_bytes = [0u8; 32];
        transcript.challenge_bytes(b"c", &mut c_scalar_bytes);
        c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);
    }
    
    // Final check: the challenge should loop back to the initial c1
    let mut final_c_bytes = [0u8; 32];
    transcript.challenge_bytes(b"c", &mut final_c_bytes);
    let final_c = Scalar::from_bytes_mod_order(final_c_bytes);
    
    let c1_option = Scalar::from_canonical_bytes(signature.c1.clone().try_into().unwrap());
    let c1 = if c1_option.is_some().into() {
        c1_option.unwrap_or(Scalar::from(0u8))
    } else {
        return Err(PyValueError::new_err("Invalid c1 in signature"))
    };
    
    // Signature is valid if the challenges match
    Ok(final_c == c1)
}

/// Reputation commitment: R = P + rep_scalar * H_rep
/// rep is an unsigned u64 bucket id; we map it to a Scalar.
#[pyfunction]
fn rep_commitment(pk_bytes: &[u8], rep: u64) -> PyResult<Vec<u8>> {
    // decompress pk (CompressedRistretto::from_slice returns Result)
let comp = match CompressedRistretto::from_slice(pk_bytes) {
    Ok(c) => c,
    Err(_) => return Err(PyValueError::new_err("invalid pk length or content")),
};
    let pk_point = comp
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid compressed pk"))?;

    // secondary generator h_generator = hash_to_ristretto(b"rep generator v1")
    let h_generator = hash_to_ristretto(b"rep generator v1");
    // map rep to scalar
    let rep_scalar = Scalar::from(rep);

    let reputation_point = pk_point + h_generator * rep_scalar;
    Ok(reputation_point.compress().to_bytes().to_vec())
}

/// Pedersen commitment structure
/// Represents a commitment of the form: C = g^v * h^r
/// where g and h are distinct generators, v is the value being committed to,
/// and r is the blinding factor (randomness)
#[pyclass]
#[derive(Clone, Debug)]
pub struct PedersenCommitment {
    #[pyo3(get)]
    pub commitment: Vec<u8>,
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub blinding_factor: Vec<u8>,
}

impl fmt::Display for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PedersenCommitment {{ commitment: {:?}, value: {} }}", 
               self.commitment, self.value)
    }
}

/// Create a Pedersen commitment of the form C = g^v * h^r
/// where g is the Ristretto basepoint, h is a domain-separated generator,
/// v is the value being committed to, and r is a random blinding factor
#[pyfunction]
fn pedersen_commit(value: u64, context: &[u8]) -> PyResult<PedersenCommitment> {
    // Use the Ristretto basepoint as g
    let g = RISTRETTO_BASEPOINT_POINT;
    
    // Generate h as a domain-separated point to avoid related discrete log problems
    // Prepend "pedersen_generator" to the context for domain separation
    let mut domain_context = Vec::with_capacity(18 + context.len());
    domain_context.extend_from_slice(b"pedersen_generator");
    domain_context.extend_from_slice(context);
    let h = hash_to_ristretto(&domain_context);
    
    // Generate a random blinding factor r
    let mut rng = OsRng;
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    
    // Convert value to a scalar
    let v = Scalar::from(value);
    
    // Compute commitment C = g^v * h^r
    let commitment_point = &v * &g + &r * &h;
    
    Ok(PedersenCommitment {
        commitment: commitment_point.compress().to_bytes().to_vec(),
        value,
        blinding_factor: r.to_bytes().to_vec(),
    })
}

/// Open a Pedersen commitment by verifying that C = g^v * h^r
/// Returns true if the commitment is valid, false otherwise
#[pyfunction]
fn pedersen_verify(commitment: &[u8], value: u64, blinding_factor: &[u8], context: &[u8]) -> PyResult<bool> {
    // Decompress the commitment
    let commitment_compressed = match CompressedRistretto::from_slice(commitment) {
        Ok(c) => c,
        Err(_) => return Err(PyValueError::new_err("invalid commitment length or content")),
    };
    let commitment_point = commitment_compressed
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid compressed commitment"))?;
    
    // Use the Ristretto basepoint as g
    let g = RISTRETTO_BASEPOINT_POINT;
    
    // Generate h as a domain-separated point (same as in commit)
    let mut domain_context = Vec::with_capacity(18 + context.len());
    domain_context.extend_from_slice(b"pedersen_generator");
    domain_context.extend_from_slice(context);
    let h = hash_to_ristretto(&domain_context);
    
    // Convert value to a scalar
    let v = Scalar::from(value);
    
    // Convert blinding factor to a scalar
    if blinding_factor.len() != 32 {
        return Err(PyValueError::new_err("blinding factor must be 32 bytes"));
    }
    let r_opt: Option<Scalar> = Scalar::from_canonical_bytes(blinding_factor.try_into().unwrap()).into();
    let r = r_opt.ok_or_else(|| PyValueError::new_err("invalid blinding factor scalar"))?;
    
    // Compute expected commitment C' = g^v * h^r
    let expected_commitment = &v * &g + &r * &h;
    
    // Check if C == C'
    Ok(commitment_point == expected_commitment)
}

/// Simple Schnorr-like signing and verification (for testing only)
/// sign: choose r random, R = r*B, c = H(R||P||m), s = r + c*sk
#[pyfunction]
fn sign_schnorr(msg: &[u8], sk_bytes: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if sk_bytes.len() != 32 {
        return Err(PyValueError::new_err("sk must be 32 bytes"));
    }

    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(sk_bytes.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("invalid sk scalar"))?;
    let pk_point: RistrettoPoint = &sk * &RISTRETTO_BASEPOINT_POINT;

    // random r via OsRng into 32 bytes then reduce
    let mut rng = OsRng;
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    let r_point = &r * &RISTRETTO_BASEPOINT_POINT;

    // challenge c = H(R||P||msg) -> wide hash then reduce
    let mut h = Sha512::new();
    h.update(r_point.compress().as_bytes());
    h.update(pk_point.compress().as_bytes());
    h.update(msg);
    let hash = h.finalize();
    let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
    let c_scalar = Scalar::from_bytes_mod_order_wide(&hash_arr);

    let s = r + c_scalar * sk;

    Ok((r_point.compress().to_bytes().to_vec(), s.to_bytes().to_vec()))
}

#[pyfunction]
fn verify_schnorr(msg: &[u8], pk_bytes: &[u8], r_bytes: &[u8], s_bytes: &[u8]) -> PyResult<bool> {
    // decompress pk and R (ComressedRistretto::from_slice -> Result)
    let comp_pk = CompressedRistretto::from_slice(pk_bytes)
        .map_err(|_| PyValueError::new_err("invalid pk length or content"))?;
    let pk_point = match comp_pk.decompress() {
        Some(p) => p,
        None => return Ok(false),
    };

    let comp_r = CompressedRistretto::from_slice(r_bytes)
        .map_err(|_| PyValueError::new_err("invalid R length or content"))?;
    let r_point = match comp_r.decompress() {
        Some(p) => p,
        None => return Ok(false),
    };

    // s scalar
    let s_opt: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes.try_into().unwrap()).into();
    let s = match s_opt {
        Some(v) => v,
        None => return Ok(false),
    };

    // recompute c = H(R||P||m) -> wide reduce
    let mut h = Sha512::new();
    h.update(r_point.compress().as_bytes());
    h.update(pk_point.compress().as_bytes());
    h.update(msg);
    let hash = h.finalize();
    let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
    let c_scalar = Scalar::from_bytes_mod_order_wide(&hash_arr);

    // check s*B == R + c*P
    let lhs = &s * &RISTRETTO_BASEPOINT_POINT;
    let rhs = r_point + pk_point * c_scalar;
    Ok(lhs == rhs)
}

/// LSAG (Linkable Spontaneous Anonymous Group) signature structure
#[pyclass]
struct LSAGSignature {
    #[pyo3(get)]
    key_image: Vec<u8>,
    #[pyo3(get)]
    c_0: Vec<u8>,
    #[pyo3(get)]
    responses: Vec<Vec<u8>>,
}

/// Sign a message with a ring of public keys using LSAG
/// 
/// Parameters:
/// - message: The message to sign
/// - ring_pubkeys: A list of public keys forming the ring
/// - secret_key: The signer's secret key
/// - signer_index: The position of the signer's public key in the ring
/// 
/// Returns:
/// - An LSAGSignature object containing the key image, initial challenge, and responses
#[pyfunction]
fn ring_sign(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, secret_key: &[u8], signer_index: usize) -> PyResult<LSAGSignature> {
    // Validate inputs
    if ring_pubkeys.is_empty() {
        return Err(PyValueError::new_err("Ring cannot be empty"));
    }
    
    if signer_index >= ring_pubkeys.len() {
        return Err(PyValueError::new_err("Signer index out of bounds"));
    }
    
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }
    
    // Convert secret key to scalar
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(secret_key.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
    
    // Decompress all public keys in the ring
    let mut ring_points = Vec::with_capacity(ring_pubkeys.len());
    for pk_bytes in &ring_pubkeys {
        let comp = CompressedRistretto::from_slice(pk_bytes)
            .map_err(|_| PyValueError::new_err("Invalid public key format"))?;
        let point = comp.decompress()
            .ok_or_else(|| PyValueError::new_err("Invalid compressed public key"))?;
        ring_points.push(point);
    }
    
    // Compute key image I = x * H_p(P)
    let pk_point = ring_points[signer_index];
    let hp = hash_to_ristretto(&pk_point.compress().to_bytes());
    let key_image = &sk * &hp;
    
    // Generate random alpha scalar
    let mut rng = OsRng;
    let mut alpha_bytes = [0u8; 32];
    rng.fill_bytes(&mut alpha_bytes);
    let alpha = Scalar::from_bytes_mod_order(alpha_bytes);
    
    // Compute L_i = alpha * G and R_i = alpha * H_p(P_i)
    let l_i = &alpha * &RISTRETTO_BASEPOINT_POINT;
    let r_i = &alpha * &hp;
    
    // Initialize c_{i+1} with H(m || L_i || R_i)
    let mut h = Sha512::new();
    h.update(message);
    h.update(l_i.compress().as_bytes());
    h.update(r_i.compress().as_bytes());
    let hash = h.finalize();
    let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
    let mut c_next = Scalar::from_bytes_mod_order_wide(&hash_arr);
    
    // Prepare responses vector
    let n = ring_pubkeys.len();
    let mut responses = Vec::with_capacity(n);
    let mut c_0 = Scalar::from(0u8);
    
    // Calculate responses for each member of the ring
    for j in 1..=n {
        let i = (signer_index + j) % n;
        
        if i == signer_index {
            // For the signer, compute response and store c_0
            responses.push(alpha - c_next * sk);
            c_0 = c_next;
            break;
        }
        
        // Generate random response for non-signer
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r_j = Scalar::from_bytes_mod_order(r_bytes);
        responses.push(r_j);
        
        // Compute L_j = r_j * G + c_j * P_j
        let l_j = &r_j * &RISTRETTO_BASEPOINT_POINT + &c_next * &ring_points[i];
        
        // Compute R_j = r_j * H_p(P_j) + c_j * I
        let hp_j = hash_to_ristretto(&ring_points[i].compress().to_bytes());
        let r_j = &r_j * &hp_j + &c_next * &key_image;
        
        // Update c_{j+1} = H(m || L_j || R_j)
        let mut h = Sha512::new();
        h.update(message);
        h.update(l_j.compress().as_bytes());
        h.update(r_j.compress().as_bytes());
        let hash = h.finalize();
        let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
        c_next = Scalar::from_bytes_mod_order_wide(&hash_arr);
    }
    
    // Convert responses to byte vectors
    let responses_bytes: Vec<Vec<u8>> = responses.into_iter()
        .map(|r| r.to_bytes().to_vec())
        .collect();
    
    Ok(LSAGSignature {
        key_image: key_image.compress().to_bytes().to_vec(),
        c_0: c_0.to_bytes().to_vec(),
        responses: responses_bytes,
    })
}

/// Verify an LSAG signature for a message and ring of public keys
/// 
/// Parameters:
/// - message: The message that was signed
/// - ring_pubkeys: The ring of public keys used in signing
/// - signature: The LSAG signature to verify
/// 
/// Returns:
/// - A tuple containing (is_valid, key_image_bytes)
#[pyfunction]
fn ring_verify(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, signature: &Bound<'_, PyAny>) -> PyResult<(bool, Vec<u8>)> {
    // Extract signature components
    let key_image_bytes = signature.getattr("key_image")?.extract::<Vec<u8>>()?;
    let c_0_bytes = signature.getattr("c_0")?.extract::<Vec<u8>>()?;
    let responses = signature.getattr("responses")?.extract::<Vec<Vec<u8>>>()?;
    
    // Validate inputs
    if ring_pubkeys.len() != responses.len() {
        return Err(PyValueError::new_err("Ring size must match number of responses"));
    }
    
    // Decompress key image
    let key_image_comp = CompressedRistretto::from_slice(&key_image_bytes)
        .map_err(|_| PyValueError::new_err("Invalid key image format"))?;
    let key_image = match key_image_comp.decompress() {
        Some(p) => p,
        None => return Ok((false, key_image_bytes)),
    };
    
    // Convert c_0 to scalar
    let c_0_opt: Option<Scalar> = Scalar::from_canonical_bytes(c_0_bytes.try_into().unwrap()).into();
    let mut c_i = match c_0_opt {
        Some(c) => c,
        None => return Ok((false, key_image_bytes)),
    };
    
    // Decompress all public keys in the ring
    let mut ring_points = Vec::with_capacity(ring_pubkeys.len());
    for pk_bytes in &ring_pubkeys {
        let comp = CompressedRistretto::from_slice(pk_bytes)
            .map_err(|_| PyValueError::new_err("Invalid public key format"))?;
        let point = match comp.decompress() {
            Some(p) => p,
            None => return Ok((false, key_image_bytes)),
        };
        ring_points.push(point);
    }
    
    // Verify the signature by checking if c_0 is correctly reconstructed
    let n = ring_pubkeys.len();
    
    for i in 0..n {
        // Convert response to scalar
        let resp_opt: Option<Scalar> = Scalar::from_canonical_bytes(responses[i].clone().try_into().unwrap()).into();
        let resp_i = match resp_opt {
            Some(r) => r,
            None => return Ok((false, key_image_bytes)),
        };
        
        // Compute L_i = r_i * G + c_i * P_i
        let l_i = &resp_i * &RISTRETTO_BASEPOINT_POINT + &c_i * &ring_points[i];
        
        // Compute H_p(P_i)
        let hp_i = hash_to_ristretto(&ring_points[i].compress().to_bytes());
        
        // Compute R_i = r_i * H_p(P_i) + c_i * I
        let r_i = &resp_i * &hp_i + &c_i * &key_image;
        
        // Compute c_{i+1} = H(m || L_i || R_i)
        let mut h = Sha512::new();
        h.update(message);
        h.update(l_i.compress().as_bytes());
        h.update(r_i.compress().as_bytes());
        let hash = h.finalize();
        let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
        c_i = Scalar::from_bytes_mod_order_wide(&hash_arr);
    }
    
    // Signature is valid if c_n = c_0
    Ok((c_i == c_0_opt.unwrap(), key_image_bytes))
}

/// Compute key image for a given secret key
/// I = x * H_p(P) where P = x * G
#[pyfunction]
fn compute_key_image(secret_key: &[u8]) -> PyResult<Vec<u8>> {
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }
    
    // Convert secret key to scalar
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(secret_key.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
    
    // Compute public key P = x * G
    let pk_point = &sk * &RISTRETTO_BASEPOINT_POINT;
    
    // Compute key image I = x * H_p(P)
    let hp = hash_to_ristretto(&pk_point.compress().to_bytes());
    let key_image = &sk * &hp;
    
    Ok(key_image.compress().to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    #[test]
    fn test_pedersen_commit_verify() {
        // Create a commitment for value 42 with context "test"
        let commitment = pedersen_commit(42, b"test").unwrap();
        
        // Verify the commitment
        let result = pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            b"test"
        ).unwrap();
        
        // Commitment should verify correctly
        assert!(result);
    }
    
    #[test]
    fn test_pedersen_binding_property() {
        // Create two commitments for the same value but with different blinding factors
        let commitment1 = pedersen_commit(100, b"binding_test").unwrap();
        let commitment2 = pedersen_commit(100, b"binding_test").unwrap();
        
        // Commitments should be different despite same value (due to different blinding factors)
        assert_ne!(commitment1.commitment, commitment2.commitment);
        
        // Each commitment should verify with its own blinding factor
        assert!(pedersen_verify(
            &commitment1.commitment, 
            commitment1.value, 
            &commitment1.blinding_factor, 
            b"binding_test"
        ).unwrap());
        
        assert!(pedersen_verify(
            &commitment2.commitment, 
            commitment2.value, 
            &commitment2.blinding_factor, 
            b"binding_test"
        ).unwrap());
        
        // Cross verification should fail (commitment1 with blinding_factor2)
        assert!(!pedersen_verify(
            &commitment1.commitment, 
            commitment1.value, 
            &commitment2.blinding_factor, 
            b"binding_test"
        ).unwrap());
    }
    
    #[test]
    fn test_pedersen_hiding_property() {
        // Create commitments for different values
        let commitment1 = pedersen_commit(123, b"hiding_test").unwrap();
        let commitment2 = pedersen_commit(456, b"hiding_test").unwrap();
        
        // Commitments should be different for different values
        assert_ne!(commitment1.commitment, commitment2.commitment);
        
        // Verify with incorrect value should fail
        assert!(!pedersen_verify(
            &commitment1.commitment, 
            456, // wrong value
            &commitment1.blinding_factor, 
            b"hiding_test"
        ).unwrap());
        
        // Verify with correct value should succeed
        assert!(pedersen_verify(
            &commitment1.commitment, 
            123, // correct value
            &commitment1.blinding_factor, 
            b"hiding_test"
        ).unwrap());
    }
    
    #[test]
    fn test_pedersen_context_separation() {
        // Create commitment with one context
        let commitment = pedersen_commit(42, b"context1").unwrap();
        
        // Verify with different context should fail
        assert!(!pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            b"context2" // different context
        ).unwrap());
        
        // Verify with correct context should succeed
        assert!(pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            b"context1" // correct context
        ).unwrap());
    }
    
    // Property-based tests for Pedersen commitments
    // Note: Proptest disabled for now due to dependency issues
    /*
    proptest! {
        // Test that commitments for different values verify correctly
        #[test]
        fn prop_pedersen_different_values_verify(value1 in 0u64..1000u64, value2 in 0u64..1000u64) {
            // Skip if values are the same
            prop_assume!(value1 != value2);
            
            let context = b"prop_test_context";
            let commitment1 = pedersen_commit(value1, context).unwrap();
            let commitment2 = pedersen_commit(value2, context).unwrap();
            
            // Each commitment should verify with its own value and blinding factor
            assert!(pedersen_verify(
                &commitment1.commitment, 
                value1, 
                &commitment1.blinding_factor, 
                context
            ).unwrap());
            
            assert!(pedersen_verify(
                &commitment2.commitment, 
                value2, 
                &commitment2.blinding_factor, 
                context
            ).unwrap());
            
            // Cross verification should fail
            assert!(!pedersen_verify(
                &commitment1.commitment, 
                value2, 
                &commitment1.blinding_factor, 
                context
            ).unwrap());
            
            assert!(!pedersen_verify(
                &commitment2.commitment, 
                value1, 
                &commitment2.blinding_factor, 
                context
            ).unwrap());
        }
        
        // Test that commitments with different contexts are distinct
        #[test]
        fn prop_pedersen_context_separation(value in 0u64..1000u64, 
                                           context1 in "[a-zA-Z0-9]{1,10}", 
                                           context2 in "[a-zA-Z0-9]{1,10}") {
            // Skip if contexts are the same
            prop_assume!(context1 != context2);
            
            let commitment1 = pedersen_commit(value, context1.as_bytes()).unwrap();
            let commitment2 = pedersen_commit(value, context2.as_bytes()).unwrap();
            
            // Commitments should be different despite same value (due to different contexts)
            assert_ne!(commitment1.commitment, commitment2.commitment);
            
            // Each commitment should verify with its own context
            assert!(pedersen_verify(
                &commitment1.commitment, 
                value, 
                &commitment1.blinding_factor, 
                context1.as_bytes()
            ).unwrap());
            
            // Cross verification should fail
            assert!(!pedersen_verify(
                &commitment1.commitment, 
                value, 
                &commitment1.blinding_factor, 
                context2.as_bytes()
            ).unwrap());
        }
    }
    */
    
    // Helper function to generate a random keypair
    fn generate_random_keypair() -> (Scalar, RistrettoPoint, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let pk = &sk * &RISTRETTO_BASEPOINT_POINT;
        let pk_bytes = pk.compress().to_bytes().to_vec();
        
        (sk, pk, sk.to_bytes().to_vec(), pk_bytes)
    }
    
    // Property tests for LSAG
    // Note: Proptest disabled for now due to dependency issues
    /*
    proptest! {
        // Test that signatures verify correctly with different ring sizes and random messages
        #[test]
        fn prop_lsag_sign_verify_different_ring_sizes(
            ring_size in 1..20usize,
            signer_index in 0..19usize, // Will be modded by ring_size
            message in vec(any::<u8>(), 1..100),
        ) {
            // Only test with valid signer indices
            let signer_idx = signer_index % ring_size;
            
            // Generate ring of keypairs
            let mut ring_pubkeys = Vec::with_capacity(ring_size);
            let mut keypairs = Vec::with_capacity(ring_size);
            
            for _ in 0..ring_size {
                let (sk, _, sk_bytes, pk_bytes) = generate_random_keypair();
                keypairs.push((sk, sk_bytes));
                ring_pubkeys.push(pk_bytes);
            }
            
            // Sign with the keypair at signer_idx
            let signature = ring_sign(&message, ring_pubkeys.clone(), &keypairs[signer_idx].1, signer_idx).unwrap();
            
            // Verify the signature
            pyo3::Python::with_gil(|py| {
                let sig_obj = pyo3::Bound::new(py, signature).unwrap();
                let (is_valid, _) = ring_verify(&message, ring_pubkeys.clone(), sig_obj.as_ref()).unwrap();
                prop_assert!(is_valid, "Signature verification failed for ring size {}", ring_size);
            });
        }
        
        // Test that signatures don't verify with tampered messages
        #[test]
        fn prop_lsag_tampered_message_fails(
            ring_size in 2..10usize,
            signer_index in 0..9usize, // Will be modded by ring_size
            message in vec(any::<u8>(), 10..50),
            tamper_index in 0..49usize, // Will be modded by message.len()
        ) {
            // Only test with valid indices
            let signer_idx = signer_index % ring_size;
            let tamper_idx = tamper_index % message.len();
            
            // Generate ring of keypairs
            let mut ring_pubkeys = Vec::with_capacity(ring_size);
            let mut keypairs = Vec::with_capacity(ring_size);
            
            for _ in 0..ring_size {
                let (sk, _, sk_bytes, pk_bytes) = generate_random_keypair();
                keypairs.push((sk, sk_bytes));
                ring_pubkeys.push(pk_bytes);
            }
            
            // Sign with the keypair at signer_idx
            let signature = ring_sign(&message, ring_pubkeys.clone(), &keypairs[signer_idx].1, signer_idx).unwrap();
            
            // Create tampered message
            let mut tampered_message = message.clone();
            tampered_message[tamper_idx] = tampered_message[tamper_idx].wrapping_add(1);
            
            // Verify with tampered message should fail
            pyo3::Python::with_gil(|py| {
                let sig_obj = pyo3::Bound::new(py, signature).unwrap();
                let (is_valid, _) = ring_verify(&tampered_message, ring_pubkeys.clone(), sig_obj.as_ref()).unwrap();
                prop_assert!(!is_valid, "Signature incorrectly verified with tampered message");
            });
        }
        
        // Test that key images are consistent for the same secret key
        #[test]
        fn prop_key_image_consistency(
            ring_size1 in 2..10usize,
            ring_size2 in 2..10usize,
            signer_index1 in 0..9usize, // Will be modded by ring_size1
            signer_index2 in 0..9usize, // Will be modded by ring_size2
            message1 in vec(any::<u8>(), 5..20),
            message2 in vec(any::<u8>(), 5..20),
        ) {
            // Only test with valid indices
            let signer_idx1 = signer_index1 % ring_size1;
            let signer_idx2 = signer_index2 % ring_size2;
            
            // Generate a keypair that will be used in both rings
            let (_, _, shared_sk_bytes, shared_pk_bytes) = generate_random_keypair();
            
            // Generate first ring
            let mut ring1 = Vec::with_capacity(ring_size1);
            ring1.push(shared_pk_bytes.clone()); // Add shared key at position 0
            for _ in 1..ring_size1 {
                let (_, _, _, pk_bytes) = generate_random_keypair();
                ring1.push(pk_bytes);
            }
            
            // Generate second ring with different size and order
            let mut ring2 = Vec::with_capacity(ring_size2);
            for _ in 0..signer_idx2 {
                let (_, _, _, pk_bytes) = generate_random_keypair();
                ring2.push(pk_bytes);
            }
            ring2.push(shared_pk_bytes.clone()); // Add shared key at position signer_idx2
            for _ in signer_idx2+1..ring_size2 {
                let (_, _, _, pk_bytes) = generate_random_keypair();
                ring2.push(pk_bytes);
            }
            
            // Sign with the shared keypair in both rings
            let sig1 = ring_sign(&message1, ring1.clone(), &shared_sk_bytes, 0).unwrap();
            let sig2 = ring_sign(&message2, ring2.clone(), &shared_sk_bytes, signer_idx2).unwrap();
            
            // Key images should be identical
            prop_assert_eq!(sig1.key_image, sig2.key_image, 
                "Key images differ for the same secret key in different rings");
        }
    }
    */
    
    #[test]
    fn test_key_image_uniqueness() {
        // Generate two different keypairs
        let (sk1, _, sk1_bytes, _) = generate_random_keypair();
        let (sk2, _, sk2_bytes, _) = generate_random_keypair();
        
        // Ensure they're different
        assert_ne!(sk1, sk2);
        
        // Compute key images
        let ki1 = compute_key_image(&sk1_bytes).unwrap();
        let ki2 = compute_key_image(&sk2_bytes).unwrap();
        
        // Key images should be different for different secret keys
        assert_ne!(ki1, ki2);
    }
    
    #[test]
    fn test_key_image_deterministic() {
        // Generate a keypair
        let (_, _, sk_bytes, _) = generate_random_keypair();
        
        // Compute key image twice
        let ki1 = compute_key_image(&sk_bytes).unwrap();
        let ki2 = compute_key_image(&sk_bytes).unwrap();
        
        // Key images should be identical for the same secret key
        assert_eq!(ki1, ki2);
    }
    
    #[test]
    fn test_lsag_sign_verify_small_ring() {
        // Create a ring of 3 keypairs
        let (sk1, _, sk1_bytes, pk1_bytes) = generate_random_keypair();
        let (_, _, _, pk2_bytes) = generate_random_keypair();
        let (_, _, _, pk3_bytes) = generate_random_keypair();
        
        let ring_pubkeys = vec![pk1_bytes.clone(), pk2_bytes, pk3_bytes];
        let message = b"test message";
        
        // Sign with the first keypair (index 0)
        let signature = ring_sign(message, ring_pubkeys.clone(), &sk1_bytes, 0).unwrap();
        
        // Create a PyObject for the signature to test the verify function
        pyo3::Python::with_gil(|py| {
            let sig_obj = pyo3::Bound::new(py, signature).unwrap();
            
            // Verify the signature
            let (is_valid, _) = ring_verify(message, ring_pubkeys.clone(), &sig_obj).unwrap();
            assert!(is_valid, "Signature verification failed");
            
            // Verify with wrong message
            let wrong_message = b"wrong message";
            let (is_valid, _) = ring_verify(wrong_message, ring_pubkeys.clone(), &sig_obj).unwrap();
            assert!(!is_valid, "Signature verified with wrong message");
        });
    }
    
    #[test]
    fn test_lsag_sign_verify_large_ring() {
        // Create a ring of 10 keypairs
        let mut ring_pubkeys = Vec::with_capacity(10);
        let mut keypairs = Vec::with_capacity(10);
        
        for _ in 0..10 {
            let (sk, _, sk_bytes, pk_bytes) = generate_random_keypair();
            keypairs.push((sk, sk_bytes));
            ring_pubkeys.push(pk_bytes);
        }
        
        let message = b"test message for large ring";
        
        // Sign with a random keypair in the ring
        let signer_index = 5; // Middle of the ring
        let signature = ring_sign(message, ring_pubkeys.clone(), &keypairs[signer_index].1, signer_index).unwrap();
        
        // Verify the signature
        pyo3::Python::with_gil(|py| {
            let sig_obj = pyo3::Bound::new(py, signature).unwrap();
            
            let (is_valid, _) = ring_verify(message, ring_pubkeys.clone(), &sig_obj).unwrap();
            assert!(is_valid, "Signature verification failed for large ring");
        });
    }
    
    #[test]
    fn test_lsag_key_image_linkability() {
        // Create a keypair
        let (_, _, sk_bytes, pk_bytes) = generate_random_keypair();
        
        // Create two different rings containing the same public key
        let (_, _, _, pk2_bytes) = generate_random_keypair();
        let (_, _, _, pk3_bytes) = generate_random_keypair();
        let (_, _, _, pk4_bytes) = generate_random_keypair();
        
        let ring1 = vec![pk_bytes.clone(), pk2_bytes.clone(), pk3_bytes.clone()];
        let ring2 = vec![pk4_bytes, pk2_bytes, pk_bytes.clone()]; // Different order
        
        let message1 = b"first message";
        let message2 = b"second message";
        
        // Sign with the same keypair in both rings
        let sig1 = ring_sign(message1, ring1.clone(), &sk_bytes, 0).unwrap();
        let sig2 = ring_sign(message2, ring2.clone(), &sk_bytes, 2).unwrap(); // Index 2 in second ring
        
        // Key images should be identical
        assert_eq!(sig1.key_image, sig2.key_image, "Key images should be identical for the same secret key");
    }
    
    #[test]
    fn test_lsag_edge_case_single_member_ring() {
        // Create a single-member ring
        let (_, _, sk_bytes, pk_bytes) = generate_random_keypair();
        let ring = vec![pk_bytes.clone()];
        let message = b"single member ring test";
        
        // Sign with the only keypair
        let signature = ring_sign(message, ring.clone(), &sk_bytes, 0).unwrap();
        
        // Verify the signature
        pyo3::Python::with_gil(|py| {
            let sig_obj = pyo3::Bound::new(py, signature).unwrap();
            
            let (is_valid, _) = ring_verify(message, ring.clone(), &sig_obj).unwrap();
            assert!(is_valid, "Signature verification failed for single-member ring");
        });
    }
    
    // CLSAG Unit Tests
    #[test]
    fn test_clsag_basic_sign_verify() {
        // Create a basic ring with 3 members
        let mut ring = Vec::with_capacity(3);
        let mut secret_keys = Vec::with_capacity(3);
        
        for i in 0..3 {
            let seed = generate_seed().unwrap();
            let (sk, pk) = derive_keypair(seed).unwrap();
            secret_keys.push(sk);
            ring.push(pk);
        }
        
        let message = b"test clsag message".to_vec();
        let signer_index = 1; // Middle of the ring
        
        // Sign with CLSAG
        let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_index], signer_index).unwrap();
        
        // Verify the signature
        let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
        assert!(is_valid, "CLSAG signature verification failed");
        
        // Tamper with message and ensure verification fails
        let tampered_message = b"tampered message".to_vec();
        let is_valid_tampered = clsag_verify(&tampered_message, ring.clone(), &signature).unwrap();
        assert!(!is_valid_tampered, "CLSAG verification should fail with tampered message");
    }
    
    #[test]
    fn test_clsag_different_ring_sizes() {
        // Test with different ring sizes
        for ring_size in [2, 4, 8, 16].iter() {
            let mut rng = OsRng;
            
            // Generate keypairs for the ring
            let mut secret_keys = Vec::with_capacity(*ring_size);
            let mut ring = Vec::with_capacity(*ring_size);
            
            for i in 0..*ring_size {
                let seed = generate_seed().unwrap();
                let (sk, pk) = derive_keypair(seed).unwrap();
                secret_keys.push(sk);
                ring.push(pk);
            }
            
            // Choose a random signer
            let signer_index = rng.next_u32() as usize % *ring_size;
            
            // Sign and verify
            let message = b"test message for different ring sizes".to_vec();
            let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_index], signer_index).unwrap();
            let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
            
            assert!(is_valid, "CLSAG signature verification failed for ring size {}", ring_size);
        }
    }
    
    #[test]
    fn test_clsag_key_image_uniqueness() {
        // Test that key images are unique per signer, not per message or ring
        let seed = generate_seed().unwrap();
        let (sk, pk) = derive_keypair(seed).unwrap();
        
        // Create two different rings, both containing the same public key
        let mut ring1 = Vec::with_capacity(3);
        let mut ring2 = Vec::with_capacity(5);
        
        // First ring
        ring1.push(pk.clone());
        for i in 0..2 {
            let seed = generate_seed().unwrap();
            let (_, pk) = derive_keypair(seed).unwrap();
            ring1.push(pk);
        }
        
        // Second ring (different size, different members except for the signer)
        for i in 0..4 {
            let seed = generate_seed().unwrap();
            let (_, pk) = derive_keypair(seed).unwrap();
            ring2.push(pk);
        }
        ring2.push(pk.clone()); // Add the same public key at a different position
        
        // Sign different messages with the same key in different rings
        let message1 = b"first message".to_vec();
        let message2 = b"second message".to_vec();
        
        let signature1 = clsag_sign(&message1, ring1.clone(), &sk, 0).unwrap(); // Index 0 in first ring
        let signature2 = clsag_sign(&message2, ring2.clone(), &sk, 4).unwrap(); // Index 4 in second ring
        
        // Key images should be identical
        assert_eq!(signature1.key_image, signature2.key_image, "Key images should be identical for the same secret key");
    }
    
    #[test]
    fn test_clsag_canonicalization() {
        // Test that ring canonicalization works correctly
        let mut rng = OsRng;
        
        // Generate 5 keypairs
        let mut secret_keys = Vec::with_capacity(5);
        let mut ring = Vec::with_capacity(5);
        
        for i in 0..5 {
            let seed = generate_seed().unwrap();
            let (sk, pk) = derive_keypair(seed).unwrap();
            secret_keys.push(sk);
            ring.push(pk);
        }
        
        // Choose a signer
        let signer_index = 2; // Middle of the ring
        
        // Create a message
        let message = b"test message for canonicalization".to_vec();
        
        // Sign with original ring order
        let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_index], signer_index).unwrap();
        
        // Shuffle the ring
        let mut shuffled_ring = ring.clone();
        shuffled_ring.swap(0, 4);
        shuffled_ring.swap(1, 3);
        
        // Verify with shuffled ring - should still work due to canonicalization
        let is_valid = clsag_verify(&message, shuffled_ring, &signature).unwrap();
        assert!(is_valid, "CLSAG signature verification failed with shuffled ring");
    }
    
    #[test]
    fn test_canonical_message_consistency() {
        // Test that canonical message format is consistent
        let submission_id = "submission123";
        let genre = "music";
        let vote_type = "upvote";
        let epoch = 1234567890;
        let nonce = "random-nonce";
        
        let message = canonical_message(submission_id, genre, vote_type, epoch, nonce).unwrap();
        
        // Create a ring and sign/verify with the canonical message
        let seed = generate_seed().unwrap();
        let (sk, pk) = derive_keypair(seed).unwrap();
        
        let ring = vec![pk.clone()];
        
        let signature = clsag_sign(&message, ring.clone(), &sk, 0).unwrap();
        let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
        
        assert!(is_valid, "Signature verification failed with canonical message");
        
        // Change one parameter and ensure the message is different
        let different_message = canonical_message(submission_id, genre, "downvote", epoch, nonce).unwrap();
        assert_ne!(message, different_message, "Canonical messages should be different with different parameters");
    }
    
    // Property tests for CLSAG
    // Note: Proptest disabled for now due to dependency issues
    /*
    proptest! {
        // Test that CLSAG signatures verify correctly with different ring sizes and random messages
        #[test]
        fn prop_clsag_sign_verify(
            ring_size in 1..10usize,
            signer_index in 0..9usize, // Will be modded by ring_size
            message in vec(any::<u8>(), 1..100),
        ) {
            // Only test with valid signer indices
            let signer_idx = signer_index % ring_size;
            
            // Generate ring of keypairs
            let mut ring = Vec::with_capacity(ring_size);
            let mut secret_keys = Vec::with_capacity(ring_size);
            
            for i in 0..ring_size {
                let seed = generate_seed().unwrap();
                let (sk, pk) = derive_keypair(&seed, format!("prop-test-{}", i).as_bytes()).unwrap();
                secret_keys.push(sk);
                ring.push(pk);
            }
            
            // Sign and verify
            let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_idx], signer_idx).unwrap();
            let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
            
            // Signature should verify
            prop_assert!(is_valid, "CLSAG signature verification failed");
            
            // Tamper with message and ensure verification fails
            if !message.is_empty() {
                let mut tampered_message = message.clone();
                tampered_message[0] = tampered_message[0].wrapping_add(1);
                
                let is_valid_tampered = clsag_verify(&tampered_message, ring.clone(), &signature).unwrap();
                prop_assert!(!is_valid_tampered, "CLSAG verification should fail with tampered message");
            }
        }
        
        // Test that canonicalization works correctly with random ring orders
        #[test]
        fn prop_clsag_canonicalization(
            ring_size in 2..10usize,
            signer_index in 0..9usize, // Will be modded by ring_size
            message in vec(any::<u8>(), 1..100),
            shuffle_seed in any::<u64>(),
        ) {
            // Only test with valid signer indices
            let signer_idx = signer_index % ring_size;
            
            // Generate ring of keypairs
            let mut ring = Vec::with_capacity(ring_size);
            let mut secret_keys = Vec::with_capacity(ring_size);
            
            for i in 0..ring_size {
                let seed = generate_seed().unwrap();
                let (sk, pk) = derive_keypair(&seed, format!("prop-test-{}", i).as_bytes()).unwrap();
                secret_keys.push(sk);
                ring.push(pk);
            }
            
            // Sign with original ring order
            let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_idx], signer_idx).unwrap();
            
            // Create a shuffled ring based on the shuffle seed
            let mut shuffled_ring = ring.clone();
            let mut rng = StdRng::seed_from_u64(shuffle_seed);
            shuffled_ring.shuffle(&mut rng);
            
            // Verify with shuffled ring - should still work due to canonicalization
            let is_valid = clsag_verify(&message, shuffled_ring, &signature).unwrap();
            prop_assert!(is_valid, "CLSAG signature verification failed with shuffled ring");
        }
    }
    */
}

#[pymodule]
fn pp_clsag_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Original functions
    m.add_function(wrap_pyfunction!(keygen_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(key_image, m)?)?;
    m.add_function(wrap_pyfunction!(rep_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(sign_schnorr, m)?)?;
    m.add_function(wrap_pyfunction!(verify_schnorr, m)?)?;
    m.add_function(wrap_pyfunction!(ring_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ring_verify, m)?)?;
    m.add_function(wrap_pyfunction!(compute_key_image, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_commit, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_blind_signature, m)?)?;
    
    // New canonical API wrappers
    m.add_function(wrap_pyfunction!(generate_seed, m)?)?;
    m.add_function(wrap_pyfunction!(derive_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(canonicalize_ring, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_message, m)?)?;
    
    // CLSAG functions
    m.add_function(wrap_pyfunction!(clsag_sign, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_verify, m)?)?;
    
    // Performance and memory management functions
    m.add_function(wrap_pyfunction!(clsag_sign_batch, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_verify_batch, m)?)?;
    
    // Classes
    m.add_class::<LSAGSignature>()?;
    m.add_class::<CLSAGSignature>()?;
    m.add_class::<PedersenCommitment>()?;
    m.add_class::<BlindRsaKeyPair>()?;
    m.add_class::<BlindedMessage>()?;
    m.add_class::<BlindSignature>()?;
    m.add_class::<PerformanceMonitor>()?;
    Ok(())
}

// ...existing code...

#[cfg(test)]
mod core_tests {
    use super::*;
    use std::time::Instant;

    struct TestVectors {
        seed: [u8; 32],
        credential: [u8; 32],
        message: Vec<u8>,
        context: Vec<u8>
    }

    impl TestVectors {
        fn new() -> Self {
            Self {
                seed: [42u8; 32],
                credential: [7u8; 32],
                message: b"test message".to_vec(),
                context: b"test-context-42".to_vec()
            }
        }
    }

    #[test]
    fn test_keygen_operations() {
        let tv = TestVectors::new();
        
        let (sk, pk) = keygen_from_seed(&tv.seed, &tv.credential).unwrap();
        assert_eq!(sk.len(), 32, "Secret key should be 32 bytes");
        assert_eq!(pk.len(), 32, "Public key should be 32 bytes");
        
        let (sk2, pk2) = keygen_from_seed(&tv.seed, &tv.credential).unwrap();
        assert_eq!(sk, sk2, "Key generation should be deterministic");
        assert_eq!(pk, pk2, "Public keys should match");
    }

    #[test]
    fn test_key_image() {
        let tv = TestVectors::new();
        let (sk, pk) = keygen_from_seed(&tv.seed, &tv.credential).unwrap();
        
        let ki = key_image(&sk, &pk, &tv.context).unwrap();
        assert_eq!(ki.len(), 32, "Key image should be 32 bytes");
        
        let ki2 = key_image(&sk, &pk, &tv.context).unwrap();
        assert_eq!(ki, ki2, "Key images should match for same inputs");
    }

    #[test]
    fn test_schnorr_signatures() {
        let tv = TestVectors::new();
        let (sk, pk) = keygen_from_seed(&tv.seed, &tv.credential).unwrap();
        
        let start = Instant::now();
        let (R, s) = sign_schnorr(&tv.message, &sk).unwrap();
        let sign_time = start.elapsed();
        
        let start = Instant::now();
        let valid = clsag_verify_batch(messages, rings, signatures).unwrap();

        let verify_time = start.elapsed();
        
        println!("Schnorr signing time: {:?}", sign_time);
        println!("Schnorr verification time: {:?}", verify_time);
        
        assert!(valid.iter().all(|x| *x), "Batch signature verification failed");
        assert!(!verify_schnorr(b"wrong message", &pk, &R, &s).unwrap());
    }

    #[test]
    fn test_batch_operations() {
        let tv = TestVectors::new();
        let batch_size = 3;
        let ring_size = 4;
        
        let mut messages = Vec::new();
        let mut rings = Vec::new();
        let mut secret_keys = Vec::new();
        let mut indices = Vec::new();
        
        for _i in 0..batch_size {
            messages.push(format!("message-{}", _i).into_bytes());
            let mut ring = Vec::new();
            
            for j in 0..ring_size {
                let seed = [(_i * ring_size + j) as u8; 32];
                let (sk, pk) = keygen_from_seed(&seed, &tv.credential).unwrap();
                if j == 0 {
                    secret_keys.push(sk);
                }
                ring.push(pk);
            }
            
            rings.push(ring);
            indices.push(0);
        }
        
        let start = Instant::now();
        let signatures = clsag_sign_batch(messages.clone(), rings.clone(), secret_keys.clone(), indices.clone()).unwrap();

        let sign_time = start.elapsed();
        
        let start = Instant::now();
        let results = clsag_verify_batch(messages, rings, signatures).unwrap();
        let verify_time = start.elapsed();
        
        println!("Batch signing time: {:?}", sign_time);
        println!("Batch verification time: {:?}", verify_time);
        
        // Check that all signatures verified successfully
        assert!(results.iter().all(|&x| x), "Batch signature verification failed");
    }
}