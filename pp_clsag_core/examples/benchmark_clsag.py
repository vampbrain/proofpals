#!/usr/bin/env python3
"""
Benchmark script for CLSAG sign and verify operations.

This script measures the performance of CLSAG operations at different ring sizes.
"""

import os
import time
import statistics
import pp_clsag_core as crypto

def benchmark_sign(ring_size, num_iterations=50):
    # Generate keypairs for the ring
    seeds = [os.urandom(32) for _ in range(ring_size)]
    keypairs = [crypto.keygen_from_seed(seed, f"participant-{i}".encode()) 
                for i, seed in enumerate(seeds)]
    
    # Extract public keys
    ring_pubkeys = [pk for _, pk in keypairs]
    
    # Choose a random signer
    signer_index = ring_size // 2
    signer_sk, _ = keypairs[signer_index]
    
    # Message to sign
    message = b"Benchmark message for CLSAG signature"
    
    # Measure sign operation
    times = []
    for _ in range(num_iterations):
        start_time = time.time()
        crypto.ring_sign(message, ring_pubkeys, signer_sk, signer_index)
        end_time = time.time()
        times.append((end_time - start_time) * 1000)  # Convert to ms
    
    avg_time = statistics.mean(times)
    ops_per_sec = 1000 / avg_time
    
    return {
        "ring_size": ring_size,
        "avg_time_ms": avg_time,
        "ops_per_sec": ops_per_sec,
        "iterations": num_iterations
    }

def benchmark_verify(ring_size, num_iterations=50):
    # Generate keypairs for the ring
    seeds = [os.urandom(32) for _ in range(ring_size)]
    keypairs = [crypto.keygen_from_seed(seed, f"participant-{i}".encode()) 
                for i, seed in enumerate(seeds)]
    
    # Extract public keys
    ring_pubkeys = [pk for _, pk in keypairs]
    
    # Choose a random signer
    signer_index = ring_size // 2
    signer_sk, _ = keypairs[signer_index]
    
    # Message to sign
    message = b"Benchmark message for CLSAG signature"
    
    # Create a signature to verify
    signature = crypto.ring_sign(message, ring_pubkeys, signer_sk, signer_index)
    
    # Measure verify operation
    times = []
    for _ in range(num_iterations):
        start_time = time.time()
        crypto.ring_verify(message, ring_pubkeys, signature)
        end_time = time.time()
        times.append((end_time - start_time) * 1000)  # Convert to ms
    
    avg_time = statistics.mean(times)
    ops_per_sec = 1000 / avg_time
    
    return {
        "ring_size": ring_size,
        "avg_time_ms": avg_time,
        "ops_per_sec": ops_per_sec,
        "iterations": num_iterations
    }

def main():
    print("CLSAG Benchmark")
    print("===============")
    
    ring_sizes = [8, 16, 32, 64]
    
    print("\nSign Operation Benchmarks:")
    print("-------------------------")
    print(f"{'Ring Size':<10} {'Ops/sec':<10} {'Avg Time (ms)':<15}")
    print("-" * 35)
    
    for size in ring_sizes:
        result = benchmark_sign(size)
        print(f"{size:<10} {result['ops_per_sec']:.2f}      {result['avg_time_ms']:.2f}")
    
    print("\nVerify Operation Benchmarks:")
    print("---------------------------")
    print(f"{'Ring Size':<10} {'Ops/sec':<10} {'Avg Time (ms)':<15}")
    print("-" * 35)
    
    for size in ring_sizes:
        result = benchmark_verify(size)
        print(f"{size:<10} {result['ops_per_sec']:.2f}      {result['avg_time_ms']:.2f}")

if __name__ == "__main__":
    main()