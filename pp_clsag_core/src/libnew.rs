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

/// Hash-to-group for arbitrary bytes -> RistrettoPoint using SHA512 -> from_uniform_bytes
fn hash_to_ristretto(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(input);
    let out = h.finalize(); // 64 bytes
    let arr: [u8; 64] = out.as_slice().try_into().expect("Sha512 output size mismatch");
    RistrettoPoint::from_uniform_bytes(&arr)
}

/// Canonicalize a ring of public keys by sorting them lexicographically
#[pyfunction]
fn canonicalize_ring(pubkeys: Vec<Vec<u8>>) -> PyResult<Vec<Vec<u8>>> {
    let mut sorted_pubkeys = pubkeys;
    sorted_pubkeys.sort();
    Ok(sorted_pubkeys)
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

/// Sign a message using CLSAG (Concise Linkable Spontaneous Anonymous Group)
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
    
    clsag_sign_single(message, &ring, signer_sk, signer_index)
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
    let ring_points: Result<Vec<RistrettoPoint>, _> = ring.iter()
        .map(|pk_bytes| {
            CompressedRistretto::from_slice(pk_bytes)
                .map_err(|_| PPCLSAGError::InvalidKeyFormat("Invalid public key format".to_string()))?
                .decompress()
                .ok_or_else(|| PPCLSAGError::InvalidKeyFormat("Failed to decompress public key".to_string()))
        })
        .collect();
    let ring_points = ring_points?;
    
    clsag_verify_single(message, &ring, &ring_points, signature)
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

/// Derive sk scalar bytes and pk bytes from a user-local seed and credential digest D.
#[pyfunction]
fn keygen_from_seed(seed: &[u8], d: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let hk = Hkdf::<Sha512>::new(Some(d), seed);
    let mut okm = [0u8; 32];
    hk.expand(b"PP-CLSAG-SK", &mut okm)
        .map_err(|_| PyValueError::new_err("hkdf expand failed"))?;

    let sk = Scalar::from_bytes_mod_order(okm);
    let pk_point: RistrettoPoint = &sk * &RISTRETTO_BASEPOINT_POINT;

    Ok((sk.to_bytes().to_vec(), pk_point.compress().to_bytes().to_vec()))
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
    keygen_from_seed(&seed, b"")
}

/// Create a canonical message format for voting
#[pyfunction]
fn canonical_message(submission_id: &str, genre: &str, vote_type: &str, epoch: u64, nonce: &str) -> PyResult<Vec<u8>> {
    let mut result = Vec::new();
    
    let id_bytes = submission_id.as_bytes();
    result.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(id_bytes);
    
    let genre_bytes = genre.as_bytes();
    result.extend_from_slice(&(genre_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(genre_bytes);
    
    let vote_type_bytes = vote_type.as_bytes();
    result.extend_from_slice(&(vote_type_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(vote_type_bytes);
    
    result.extend_from_slice(&epoch.to_be_bytes());
    
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

    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(sk_bytes.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("invalid sk scalar"))?;

    let mut buf = Vec::with_capacity(pk_bytes.len() + context.len());
    buf.extend_from_slice(pk_bytes);
    buf.extend_from_slice(context);

    let hp = hash_to_ristretto(&buf);
    let key_image_point = &sk * &hp;
    Ok(key_image_point.compress().to_bytes().to_vec())
}

/// Reputation commitment: R = P + rep_scalar * H_rep
#[pyfunction]
fn rep_commitment(pk_bytes: &[u8], rep: u64) -> PyResult<Vec<u8>> {
    let comp = match CompressedRistretto::from_slice(pk_bytes) {
        Ok(c) => c,
        Err(_) => return Err(PyValueError::new_err("invalid pk length or content")),
    };
    let pk_point = comp
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid compressed pk"))?;

    let h_generator = hash_to_ristretto(b"rep generator v1");
    let rep_scalar = Scalar::from(rep);

    let reputation_point = pk_point + h_generator * rep_scalar;
    Ok(reputation_point.compress().to_bytes().to_vec())
}

/// Pedersen commitment structure
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
#[pyfunction]
fn pedersen_commit(value: u64, context: &[u8]) -> PyResult<PedersenCommitment> {
    let g = RISTRETTO_BASEPOINT_POINT;
    
    let mut domain_context = Vec::with_capacity(18 + context.len());
    domain_context.extend_from_slice(b"pedersen_generator");
    domain_context.extend_from_slice(context);
    let h = hash_to_ristretto(&domain_context);
    
    let mut rng = OsRng;
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    
    let v = Scalar::from(value);
    let commitment_point = &v * &g + &r * &h;
    
    Ok(PedersenCommitment {
        commitment: commitment_point.compress().to_bytes().to_vec(),
        value,
        blinding_factor: r.to_bytes().to_vec(),
    })
}

/// Open a Pedersen commitment by verifying that C = g^v * h^r
#[pyfunction]
fn pedersen_verify(commitment: &[u8], value: u64, blinding_factor: &[u8], context: &[u8]) -> PyResult<bool> {
    let commitment_compressed = match CompressedRistretto::from_slice(commitment) {
        Ok(c) => c,
        Err(_) => return Err(PyValueError::new_err("invalid commitment length or content")),
    };
    let commitment_point = commitment_compressed
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid compressed commitment"))?;
    
    let g = RISTRETTO_BASEPOINT_POINT;
    
    let mut domain_context = Vec::with_capacity(18 + context.len());
    domain_context.extend_from_slice(b"pedersen_generator");
    domain_context.extend_from_slice(context);
    let h = hash_to_ristretto(&domain_context);
    
    let v = Scalar::from(value);
    
    if blinding_factor.len() != 32 {
        return Err(PyValueError::new_err("blinding factor must be 32 bytes"));
    }
    let r_opt: Option<Scalar> = Scalar::from_canonical_bytes(blinding_factor.try_into().unwrap()).into();
    let r = r_opt.ok_or_else(|| PyValueError::new_err("invalid blinding factor scalar"))?;
    
    let expected_commitment = &v * &g + &r * &h;
    
    Ok(commitment_point == expected_commitment)
}

/// Simple Schnorr-like signing and verification
#[pyfunction]
fn sign_schnorr(msg: &[u8], sk_bytes: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if sk_bytes.len() != 32 {
        return Err(PyValueError::new_err("sk must be 32 bytes"));
    }

    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(sk_bytes.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("invalid sk scalar"))?;
    let pk_point: RistrettoPoint = &sk * &RISTRETTO_BASEPOINT_POINT;

    let mut rng = OsRng;
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    let r_point = &r * &RISTRETTO_BASEPOINT_POINT;

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

    let s_opt: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes.try_into().unwrap()).into();
    let s = match s_opt {
        Some(v) => v,
        None => return Ok(false),
    };

    let mut h = Sha512::new();
    h.update(r_point.compress().as_bytes());
    h.update(pk_point.compress().as_bytes());
    h.update(msg);
    let hash = h.finalize();
    let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
    let c_scalar = Scalar::from_bytes_mod_order_wide(&hash_arr);

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
#[pyfunction]
fn ring_sign(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, secret_key: &[u8], signer_index: usize) -> PyResult<LSAGSignature> {
    if ring_pubkeys.is_empty() {
        return Err(PyValueError::new_err("Ring cannot be empty"));
    }
    
    if signer_index >= ring_pubkeys.len() {
        return Err(PyValueError::new_err("Signer index out of bounds"));
    }
    
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }
    
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(secret_key.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
    
    let mut ring_points = Vec::with_capacity(ring_pubkeys.len());
    for pk_bytes in &ring_pubkeys {
        let comp = CompressedRistretto::from_slice(pk_bytes)
            .map_err(|_| PyValueError::new_err("Invalid public key format"))?;
        let point = comp.decompress()
            .ok_or_else(|| PyValueError::new_err("Invalid compressed public key"))?;
        ring_points.push(point);
    }
    
    let pk_point = ring_points[signer_index];
    let hp = hash_to_ristretto(&pk_point.compress().to_bytes());
    let key_image = &sk * &hp;
    
    let mut rng = OsRng;
    let mut alpha_bytes = [0u8; 32];
    rng.fill_bytes(&mut alpha_bytes);
    let alpha = Scalar::from_bytes_mod_order(alpha_bytes);
    
    let l_i = &alpha * &RISTRETTO_BASEPOINT_POINT;
    let r_i = &alpha * &hp;
    
    let mut h = Sha512::new();
    h.update(message);
    h.update(l_i.compress().as_bytes());
    h.update(r_i.compress().as_bytes());
    let hash = h.finalize();
    let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
    let mut c_next = Scalar::from_bytes_mod_order_wide(&hash_arr);
    
    let n = ring_pubkeys.len();
    let mut responses = Vec::with_capacity(n);
    let mut c_0 = Scalar::from(0u8);
    
    for j in 1..=n {
        let i = (signer_index + j) % n;
        
        if i == signer_index {
            responses.push(alpha - c_next * sk);
            c_0 = c_next;
            break;
        }
        
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r_j = Scalar::from_bytes_mod_order(r_bytes);
        responses.push(r_j);
        
        let l_j = &r_j * &RISTRETTO_BASEPOINT_POINT + &c_next * &ring_points[i];
        
        let hp_j = hash_to_ristretto(&ring_points[i].compress().to_bytes());
        let r_j = &r_j * &hp_j + &c_next * &key_image;
        
        let mut h = Sha512::new();
        h.update(message);
        h.update(l_j.compress().as_bytes());
        h.update(r_j.compress().as_bytes());
        let hash = h.finalize();
        let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
        c_next = Scalar::from_bytes_mod_order_wide(&hash_arr);
    }
    
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
#[pyfunction]
fn ring_verify(message: &[u8], ring_pubkeys: Vec<Vec<u8>>, signature: &Bound<'_, PyAny>) -> PyResult<(bool, Vec<u8>)> {
    let key_image_bytes = signature.getattr("key_image")?.extract::<Vec<u8>>()?;
    let c_0_bytes = signature.getattr("c_0")?.extract::<Vec<u8>>()?;
    let responses = signature.getattr("responses")?.extract::<Vec<Vec<u8>>>()?;
    
    if ring_pubkeys.len() != responses.len() {
        return Err(PyValueError::new_err("Ring size must match number of responses"));
    }
    
    let key_image_comp = CompressedRistretto::from_slice(&key_image_bytes)
        .map_err(|_| PyValueError::new_err("Invalid key image format"))?;
    let key_image = match key_image_comp.decompress() {
        Some(p) => p,
        None => return Ok((false, key_image_bytes)),
    };
    
    let c_0_opt: Option<Scalar> = Scalar::from_canonical_bytes(c_0_bytes.try_into().unwrap()).into();
    let mut c_i = match c_0_opt {
        Some(c) => c,
        None => return Ok((false, key_image_bytes)),
    };
    
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
    
    let n = ring_pubkeys.len();
    
    for i in 0..n {
        let resp_opt: Option<Scalar> = Scalar::from_canonical_bytes(responses[i].clone().try_into().unwrap()).into();
        let resp_i = match resp_opt {
            Some(r) => r,
            None => return Ok((false, key_image_bytes)),
        };
        
        let l_i = &resp_i * &RISTRETTO_BASEPOINT_POINT + &c_i * &ring_points[i];
        
        let hp_i = hash_to_ristretto(&ring_points[i].compress().to_bytes());
        let r_i = &resp_i * &hp_i + &c_i * &key_image;
        
        let mut h = Sha512::new();
        h.update(message);
        h.update(l_i.compress().as_bytes());
        h.update(r_i.compress().as_bytes());
        let hash = h.finalize();
        let hash_arr: [u8; 64] = hash.as_slice().try_into().unwrap();
        c_i = Scalar::from_bytes_mod_order_wide(&hash_arr);
    }
    
    Ok((c_i == c_0_opt.unwrap(), key_image_bytes))
}

/// Compute key image for a given secret key
#[pyfunction]
fn compute_key_image(secret_key: &[u8]) -> PyResult<Vec<u8>> {
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }
    
    let sk_opt: Option<Scalar> = Scalar::from_canonical_bytes(secret_key.try_into().unwrap()).into();
    let sk = sk_opt.ok_or_else(|| PyValueError::new_err("Invalid secret key"))?;
    
    let pk_point = &sk * &RISTRETTO_BASEPOINT_POINT;
    let hp = hash_to_ristretto(&pk_point.compress().to_bytes());
    let key_image = &sk * &hp;
    
    Ok(key_image.compress().to_bytes().to_vec())
}

#[pymodule]
fn pp_clsag_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_function(wrap_pyfunction!(generate_seed, m)?)?;
    m.add_function(wrap_pyfunction!(derive_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(canonicalize_ring, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_message, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_sign, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_verify, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_sign_batch, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_verify_batch, m)?)?;
    
    m.add_class::<LSAGSignature>()?;
    m.add_class::<CLSAGSignature>()?;
    m.add_class::<PedersenCommitment>()?;
    m.add_class::<BlindRsaKeyPair>()?;
    m.add_class::<BlindedMessage>()?;
    m.add_class::<BlindSignature>()?;
    m.add_class::<PerformanceMonitor>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::time::Instant;

    // ===== Test Utilities =====
    
    struct TestVectors {
        seed: [u8; 32],
        credential: [u8; 32],
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl TestVectors {
        fn new() -> Self {
            Self {
                seed: [42u8; 32],
                credential: [7u8; 32],
                message: b"test message".to_vec(),
                context: b"test-context-42".to_vec(),
            }
        }
    }

    fn generate_random_keypair() -> (Scalar, RistrettoPoint, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let pk = &sk * &RISTRETTO_BASEPOINT_POINT;
        let pk_bytes = pk.compress().to_bytes().to_vec();
        
        (sk, pk, sk.to_bytes().to_vec(), pk_bytes)
    }

    // ===== Core Cryptographic Operations Tests =====
    
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

    // ===== Schnorr Signature Tests =====
    
    #[test]
    fn test_schnorr_sign_verify() {
        let tv = TestVectors::new();
        let (sk, pk) = keygen_from_seed(&tv.seed, &tv.credential).unwrap();
        
        let start = Instant::now();
        let (r, s) = sign_schnorr(&tv.message, &sk).unwrap();
        let sign_time = start.elapsed();
        
        let start = Instant::now();
        let valid = verify_schnorr(&tv.message, &pk, &r, &s).unwrap();
        let verify_time = start.elapsed();
        
        println!("Schnorr signing time: {:?}", sign_time);
        println!("Schnorr verification time: {:?}", verify_time);
        
        assert!(valid, "Valid signature should verify");
        assert!(!verify_schnorr(b"wrong message", &pk, &r, &s).unwrap(), 
                "Wrong message should not verify");
    }

    // ===== LSAG Tests =====
    
    #[test]
    fn test_lsag_sign_verify_small_ring() {
        let (_, _, sk1_bytes, pk1_bytes) = generate_random_keypair();
        let (_, _, _, pk2_bytes) = generate_random_keypair();
        let (_, _, _, pk3_bytes) = generate_random_keypair();
        
        let ring_pubkeys = vec![pk1_bytes.clone(), pk2_bytes, pk3_bytes];
        let message = b"test message";
        
        let signature = ring_sign(message, ring_pubkeys.clone(), &sk1_bytes, 0).unwrap();
        
        pyo3::Python::with_gil(|py| {
            let sig_obj = pyo3::Bound::new(py, signature).unwrap();
            let (is_valid, _) = ring_verify(message, ring_pubkeys.clone(), &sig_obj).unwrap();
            assert!(is_valid, "LSAG signature should verify");
            
            let wrong_message = b"wrong message";
            let (is_valid, _) = ring_verify(wrong_message, ring_pubkeys.clone(), &sig_obj).unwrap();
            assert!(!is_valid, "Wrong message should not verify");
        });
    }
    
    #[test]
    fn test_lsag_key_image_linkability() {
        let (_, _, sk_bytes, pk_bytes) = generate_random_keypair();
        let (_, _, _, pk2_bytes) = generate_random_keypair();
        let (_, _, _, pk3_bytes) = generate_random_keypair();
        
        let ring1 = vec![pk_bytes.clone(), pk2_bytes.clone(), pk3_bytes.clone()];
        let ring2 = vec![pk3_bytes, pk2_bytes, pk_bytes.clone()];
        
        let message1 = b"first message";
        let message2 = b"second message";
        
        let sig1 = ring_sign(message1, ring1, &sk_bytes, 0).unwrap();
        let sig2 = ring_sign(message2, ring2, &sk_bytes, 2).unwrap();
        
        assert_eq!(sig1.key_image, sig2.key_image, 
                   "Key images should be identical for the same secret key");
    }

    // ===== CLSAG Tests =====
    
    #[test]
    fn test_clsag_basic_sign_verify() {
        let mut ring = Vec::with_capacity(3);
        let mut secret_keys = Vec::with_capacity(3);
        
        for _ in 0..3 {
            let seed = generate_seed().unwrap();
            let (sk, pk) = derive_keypair(seed).unwrap();
            secret_keys.push(sk);
            ring.push(pk);
        }
        
        let message = b"test clsag message".to_vec();
        let signer_index = 1;
        
        let signature = clsag_sign(&message, ring.clone(), &secret_keys[signer_index], signer_index).unwrap();
        let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
        assert!(is_valid, "CLSAG signature should verify");
        
        let tampered_message = b"tampered message".to_vec();
        let is_valid_tampered = clsag_verify(&tampered_message, ring.clone(), &signature).unwrap();
        assert!(!is_valid_tampered, "Tampered message should not verify");
    }
    
    #[test]
    fn test_clsag_key_image_uniqueness() {
        let seed = generate_seed().unwrap();
        let (sk, pk) = derive_keypair(seed).unwrap();
        
        let mut ring1 = Vec::with_capacity(3);
        let mut ring2 = Vec::with_capacity(5);
        
        ring1.push(pk.clone());
        for _ in 0..2 {
            let seed = generate_seed().unwrap();
            let (_, pk) = derive_keypair(seed).unwrap();
            ring1.push(pk);
        }
        
        for _ in 0..4 {
            let seed = generate_seed().unwrap();
            let (_, pk) = derive_keypair(seed).unwrap();
            ring2.push(pk);
        }
        ring2.push(pk.clone());
        
        let message1 = b"first message".to_vec();
        let message2 = b"second message".to_vec();
        
        let signature1 = clsag_sign(&message1, ring1, &sk, 0).unwrap();
        let signature2 = clsag_sign(&message2, ring2, &sk, 4).unwrap();
        
        assert_eq!(signature1.key_image, signature2.key_image, 
                   "Key images should be identical for the same secret key");
    }
    
    #[test]
    fn test_clsag_batch_operations() {
        let tv = TestVectors::new();
        let batch_size = 3;
        let ring_size = 4;
        
        let mut messages = Vec::new();
        let mut ring = Vec::new();
        let mut secret_keys = Vec::new();
        let mut indices = Vec::new();
        
        for j in 0..ring_size {
            let seed = [(j * 10) as u8; 32];
            let (sk, pk) = keygen_from_seed(&seed, &tv.credential).unwrap();
            if j == 0 {
                secret_keys.push(sk.clone());
            }
            ring.push(pk);
        }
        
        for i in 0..batch_size {
            messages.push(format!("message-{}", i).into_bytes());
            if i > 0 {
                secret_keys.push(secret_keys[0].clone());
            }
            indices.push(0);
        }
        
        let start = Instant::now();
        let signatures = clsag_sign_batch(messages.clone(), ring.clone(), secret_keys, indices).unwrap();
        let sign_time = start.elapsed();
        
        let start = Instant::now();
        let results = clsag_verify_batch(messages, ring, signatures).unwrap();
        let verify_time = start.elapsed();
        
        println!("CLSAG batch signing time ({} sigs): {:?}", batch_size, sign_time);
        println!("CLSAG batch verification time ({} sigs): {:?}", batch_size, verify_time);
        
        assert_eq!(results.len(), batch_size);
        assert!(results.iter().all(|&x| x), "All batch signatures should verify");
    }

    // ===== Blind RSA Tests =====
    
    #[test]
    fn test_blind_rsa_keypair_generation() {
        let keypair = BlindRsaKeyPair::new(1024).unwrap();
        assert_eq!(keypair.bits, 1024);
        
        let public_key = keypair.export_public_key();
        assert!(public_key.len() > 0, "Public key should be exported");
    }
    
    #[test]
    fn test_blind_rsa_invalid_key_sizes() {
        let result = BlindRsaKeyPair::new(256);
        assert!(result.is_err(), "Should reject key size < 512");
        
        let result = BlindRsaKeyPair::new(16384);
        assert!(result.is_err(), "Should reject key size > 8192");
    }
    
    #[test]
    fn test_blind_rsa_end_to_end() {
        let server_keypair = BlindRsaKeyPair::new(1024).unwrap();
        let public_key = server_keypair.export_public_key();
        
        let message = b"This is a test message for blind RSA";
        
        let blinded_message = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data = blinded_message.get_blinded_message();
        
        let blind_signature = server_keypair.sign_blinded_message(&blinded_data).unwrap();
        let unblinded_signature = blinded_message.unblind(&blind_signature, &public_key).unwrap();
        
        let is_valid = verify_blind_signature(message, &unblinded_signature, &public_key).unwrap();
        assert!(is_valid, "Unblinded signature should verify");
        
        let wrong_is_valid = verify_blind_signature(b"wrong message", &unblinded_signature, &public_key).unwrap();
        assert!(!wrong_is_valid, "Wrong message should not verify");
    }
    
    #[test]
    fn test_blind_rsa_unlinkability() {
        let server_keypair = BlindRsaKeyPair::new(1024).unwrap();
        let public_key = server_keypair.export_public_key();
        
        let message = b"This is a test message";
        let blinded_message1 = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data1 = blinded_message1.get_blinded_message();
        
        let blinded_message2 = BlindedMessage::blind(message, &public_key).unwrap();
        let blinded_data2 = blinded_message2.get_blinded_message();
        
        assert_ne!(blinded_data1, blinded_data2, "Blinded messages should be different");
        
        let blind_signature1 = server_keypair.sign_blinded_message(&blinded_data1).unwrap();
        let blind_signature2 = server_keypair.sign_blinded_message(&blinded_data2).unwrap();
        
        let unblinded_signature1 = blinded_message1.unblind(&blind_signature1, &public_key).unwrap();
        let unblinded_signature2 = blinded_message2.unblind(&blind_signature2, &public_key).unwrap();
        
        assert_ne!(unblinded_signature1, unblinded_signature2);
        
        let is_valid1 = verify_blind_signature(message, &unblinded_signature1, &public_key).unwrap();
        let is_valid2 = verify_blind_signature(message, &unblinded_signature2, &public_key).unwrap();
        
        assert!(is_valid1);
        assert!(is_valid2);
    }

    // ===== Pedersen Commitment Tests =====
    
    #[test]
    fn test_pedersen_commit_verify() {
        let value = 42;
        let context = b"test";
        
        let commitment = pedersen_commit(value, context).unwrap();
        
        let result = pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            context
        ).unwrap();
        
        assert!(result, "Pedersen commitment should verify");
    }
    
    #[test]
    fn test_pedersen_binding_property() {
        let commitment1 = pedersen_commit(100, b"binding_test").unwrap();
        let commitment2 = pedersen_commit(100, b"binding_test").unwrap();
        
        assert_ne!(commitment1.commitment, commitment2.commitment, 
                   "Commitments should differ despite same value");
        
        assert!(pedersen_verify(
            &commitment1.commitment, 
            commitment1.value, 
            &commitment1.blinding_factor, 
            b"binding_test"
        ).unwrap());
        
        assert!(!pedersen_verify(
            &commitment1.commitment, 
            commitment1.value, 
            &commitment2.blinding_factor, 
            b"binding_test"
        ).unwrap());
    }
    
    #[test]
    fn test_pedersen_hiding_property() {
        let commitment1 = pedersen_commit(123, b"hiding_test").unwrap();
        let commitment2 = pedersen_commit(456, b"hiding_test").unwrap();
        
        assert_ne!(commitment1.commitment, commitment2.commitment);
        
        assert!(!pedersen_verify(
            &commitment1.commitment, 
            456,
            &commitment1.blinding_factor, 
            b"hiding_test"
        ).unwrap());
        
        assert!(pedersen_verify(
            &commitment1.commitment, 
            123,
            &commitment1.blinding_factor, 
            b"hiding_test"
        ).unwrap());
    }
    
    #[test]
    fn test_pedersen_context_separation() {
        let commitment = pedersen_commit(42, b"context1").unwrap();
        
        assert!(!pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            b"context2"
        ).unwrap());
        
        assert!(pedersen_verify(
            &commitment.commitment, 
            commitment.value, 
            &commitment.blinding_factor, 
            b"context1"
        ).unwrap());
    }

    // ===== Memory Management Tests =====
    
    #[test]
    fn test_secure_memory() {
        let mut mem = SecureMemory::new(32);
        let slice = mem.as_mut_slice();
        
        slice[0] = 42;
        slice[1] = 7;
        
        assert_eq!(mem.as_slice()[0], 42);
        assert_eq!(mem.as_slice()[1], 7);
    }
    
    #[test]
    fn test_crypto_memory_pool() {
        let mut pool = CryptoMemoryPool::new(10);
        
        let scalar = Scalar::from(42u64);
        pool.return_scalar(scalar);
        
        let retrieved = pool.get_scalar();
        assert_eq!(retrieved, scalar);
        
        pool.clear();
        assert_eq!(pool.scalar_pool.len(), 0);
    }
    
    #[test]
    fn test_performance_monitor() {
        let mut monitor = PerformanceMonitor::new();
        
        assert_eq!(monitor.operation_count, 0);
        assert_eq!(monitor.total_time_ms, 0.0);
        
        monitor.record_operation(10.0);
        monitor.record_operation(20.0);
        monitor.record_operation(30.0);
        
        assert_eq!(monitor.operation_count, 3);
        assert_eq!(monitor.total_time_ms, 60.0);
        assert_eq!(monitor.average_time_ms, 20.0);
        
        monitor.reset();
        assert_eq!(monitor.operation_count, 0);
    }

    // ===== Canonical Message Tests =====
    
    #[test]
    fn test_canonical_message_consistency() {
        let submission_id = "submission123";
        let genre = "music";
        let vote_type = "upvote";
        let epoch = 1234567890;
        let nonce = "random-nonce";
        
        let message = canonical_message(submission_id, genre, vote_type, epoch, nonce).unwrap();
        
        let seed = generate_seed().unwrap();
        let (sk, pk) = derive_keypair(seed).unwrap();
        
        let ring = vec![pk.clone()];
        
        let signature = clsag_sign(&message, ring.clone(), &sk, 0).unwrap();
        let is_valid = clsag_verify(&message, ring.clone(), &signature).unwrap();
        
        assert!(is_valid, "Signature should verify with canonical message");
        
        let different_message = canonical_message(submission_id, genre, "downvote", epoch, nonce).unwrap();
        assert_ne!(message, different_message, "Different parameters should produce different messages");
    }
    
    // ===== Key Image Tests =====
    
    #[test]
    fn test_key_image_uniqueness() {
        let (_, _, sk1_bytes, _) = generate_random_keypair();
        let (_, _, sk2_bytes, _) = generate_random_keypair();
        
        let ki1 = compute_key_image(&sk1_bytes).unwrap();
        let ki2 = compute_key_image(&sk2_bytes).unwrap();
        
        assert_ne!(ki1, ki2, "Different keys should produce different key images");
    }
    
    #[test]
    fn test_key_image_deterministic() {
        let (_, _, sk_bytes, _) = generate_random_keypair();
        
        let ki1 = compute_key_image(&sk_bytes).unwrap();
        let ki2 = compute_key_image(&sk_bytes).unwrap();
        
        assert_eq!(ki1, ki2, "Same key should produce same key image");
    }
}