// src/lib/crypto/key-manager.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

interface CryptoStore {
  seed: Uint8Array | null;
  keyPair: KeyPair | null;
  tokens: string[];
  publicKeyHex: string | null; // Server-generated public key
  
  // Actions
  generateKeyPair: () => Promise<void>;
  fetchPublicKey: () => Promise<void>;
  hasKeyPair: () => boolean;
  setSeed: (seed: Uint8Array) => void;
  setKeyPair: (keyPair: KeyPair) => void;
  setPublicKeyHex: (publicKeyHex: string) => void;
  addTokens: (tokens: string[]) => void;
  consumeToken: (tokenId: string) => void;
  clearAll: () => void;
  getPublicKeyHex: () => string | null;
}

// WARNING: In production, consider using IndexedDB with encryption
// or prompting for passphrase on each session
export const useCryptoStore = create<CryptoStore>()(
  persist(
    (set, get) => ({
      seed: null,
      keyPair: null,
      tokens: [],
      publicKeyHex: null,
      
      generateKeyPair: async () => {
        try {
          console.log('🔐 Initializing crypto module...');
          await SecureKeyManager.initialize();
          console.log('✅ Crypto module initialized');
          
          console.log('🎲 Generating seed...');
          const seed = SecureKeyManager.generateSeed();
          console.log('✅ Seed generated:', seed.length, 'bytes');
          
          console.log('🔑 Deriving key pair...');
          const keyPair = SecureKeyManager.deriveKeyPair(seed);
          console.log('✅ Key pair derived - Secret:', keyPair.secretKey.length, 'bytes, Public:', keyPair.publicKey.length, 'bytes');
          
          set({ seed, keyPair });
          console.log('✅ Keys stored in crypto store');
        } catch (error) {
          console.error('❌ Failed to generate key pair:', error);
          throw error;
        }
      },

      fetchPublicKey: async () => {
        try {
          console.log('🔐 Fetching public key from server...');
          const { apiClient } = await import('@/lib/api/client');
          
          const response = await apiClient.get('/api/v1/auth/public-key') as {
            success: boolean;
            public_key_hex?: string;
            message?: string;
          };
          
          if (response.success && response.public_key_hex) {
            set({ publicKeyHex: response.public_key_hex });
            console.log('✅ Public key fetched from server:', response.public_key_hex.substring(0, 16) + '...');
          } else {
            throw new Error('Failed to fetch public key from server');
          }
        } catch (error) {
          console.error('❌ Failed to fetch public key:', error);
          throw error;
        }
      },
      
      hasKeyPair: () => {
        const state = get();
        return state.keyPair !== null || state.publicKeyHex !== null;
      },
      
      setSeed: (seed) => set({ seed }),
      
      setKeyPair: (keyPair) => set({ keyPair }),

      setPublicKeyHex: (publicKeyHex) => set({ publicKeyHex }),
      
      addTokens: (tokens) => set((state) => ({
        tokens: [...state.tokens, ...tokens],
      })),
      
      consumeToken: (tokenId) => set((state) => ({
        tokens: state.tokens.filter((t) => t !== tokenId),
      })),
      
      getPublicKeyHex: () => {
        const state = get();
        // Prefer server-generated public key
        if (state.publicKeyHex) {
          return state.publicKeyHex;
        }
        // Fallback to locally generated key
        const kp = state.keyPair;
        if (!kp) return null;
        return Array.from(kp.publicKey).map((b) => b.toString(16).padStart(2, '0')).join('');
      },

      clearAll: () => set({
        seed: null,
        keyPair: null,
        tokens: [],
        publicKeyHex: null,
      }),
    }),
    {
      name: 'proofpals-crypto',
      // Store keyPair and tokens for testing - in production use proper encryption
      partialize: (state) => ({
        keyPair: state.keyPair, // Persist for testing
        tokens: state.tokens,
        publicKeyHex: state.publicKeyHex, // Persist server-generated public key
      }),
    }
  )
);

export class SecureKeyManager {
  private static wasm: any;

  static async initialize() {
    if (!this.wasm) {
      // Load WASM module
      // Use local stub/module to avoid unresolved import errors in Vite.
      // Replace with actual WASM module when available.
      this.wasm = await import('@/lib/crypto/pp_clsag_core_wasm');
      await this.wasm.default(); // Initialize WASM
    }
  }

  static generateSeed(): Uint8Array {
    if (!this.wasm) throw new Error('WASM not initialized');
    return this.wasm.generate_seed();
  }

  static deriveKeyPair(seed: Uint8Array): KeyPair {
    if (!this.wasm) throw new Error('WASM not initialized');
    const [secretKey, publicKey] = this.wasm.derive_keypair(seed);
    return { secretKey, publicKey };
  }

  static computeKeyImage(
    secretKey: Uint8Array,
    publicKey: Uint8Array,
    context: Uint8Array
  ): Uint8Array {
    if (!this.wasm) throw new Error('WASM not initialized');
    return this.wasm.key_image(secretKey, publicKey, context);
  }

  static async createCanonicalMessage(params: {
    submissionId: string;
    genre: string;
    voteType: string;
    epoch: number;
    nonce: string;
  }): Promise<Uint8Array> {
    // Create a canonical message format for voting
    const messageString = `${params.submissionId}:${params.genre}:${params.voteType}:${params.epoch}:${params.nonce}`;
    return new TextEncoder().encode(messageString);
  }

  static async signVote(
    message: Uint8Array,
    ring: Uint8Array[],
    secretKey: Uint8Array,
    signerIndex: number
  ): Promise<any> {
    if (!this.wasm) throw new Error('WASM not initialized');
    return this.wasm.clsag_sign(message, ring, secretKey, signerIndex);
  }

  // Secure cleanup
  static clearSensitiveData() {
    useCryptoStore.getState().clearAll();
    
    // Additional cleanup if needed
    if (typeof window !== 'undefined') {
      sessionStorage.clear();
      // Don't clear localStorage - may have user preferences
    }
  }
}