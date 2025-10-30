// src/hooks/useSystemInitialization.ts
import { useEffect, useState } from 'react';
import { decentralizedSystem } from '@/lib/integration/decentralizedSystem';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { toast } from 'sonner';

export interface SystemInitializationStatus {
  isInitialized: boolean;
  isInitializing: boolean;
  error: string | null;
  cryptoReady: boolean;
  backendReady: boolean;
}

export function useSystemInitialization() {
  const [status, setStatus] = useState<SystemInitializationStatus>({
    isInitialized: false,
    isInitializing: false,
    error: null,
    cryptoReady: false,
    backendReady: false
  });

  const { hasKeyPair, fetchPublicKey } = useCryptoStore();

  const initializeSystem = async () => {
    setStatus(prev => ({ ...prev, isInitializing: true, error: null }));

    try {
      // First, try to fetch public key from server
      try {
        await fetchPublicKey();
        console.log('✅ Public key fetched from server');
      } catch (error) {
        console.warn('⚠️ Could not fetch public key from server, will use local generation:', error);
      }

      // Initialize the decentralized system
      const result = await decentralizedSystem.initialize();
      
      setStatus({
        isInitialized: result.success,
        isInitializing: false,
        error: result.success ? null : 'System initialization failed',
        cryptoReady: result.status.crypto.wasmLoaded && result.status.crypto.keyGeneration,
        backendReady: result.status.backend.database && result.status.backend.votingEndpoints
      });

      if (result.success) {
        toast.success('System initialized successfully!');
      } else {
        toast.warning('System partially initialized - some features may not work');
      }

    } catch (error: any) {
      const errorMessage = error.message || 'Unknown initialization error';
      setStatus({
        isInitialized: false,
        isInitializing: false,
        error: errorMessage,
        cryptoReady: false,
        backendReady: false
      });
      toast.error(`Initialization failed: ${errorMessage}`);
    }
  };

  // Auto-initialize on mount if not already done
  useEffect(() => {
    if (!status.isInitialized && !status.isInitializing) {
      initializeSystem();
    }
  }, []);

  // Re-initialize if crypto keys are generated
  useEffect(() => {
    if (hasKeyPair() && !status.cryptoReady) {
      initializeSystem();
    }
  }, [hasKeyPair()]);

  return {
    ...status,
    initializeSystem
  };
}
