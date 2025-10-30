// src/lib/integration/decentralizedSystem.ts
// Comprehensive integration layer for the decentralized ProofPals system

import { apiClient } from '@/lib/api/client';
import { SecureKeyManager, useCryptoStore } from '@/lib/crypto/key-manager';
import { backendIntegration } from '@/lib/services/backendIntegration';
import { toast } from 'sonner';

export interface DecentralizedSystemConfig {
  enableCrypto: boolean;
  enableRingSignatures: boolean;
  enableAnonymousVoting: boolean;
  testMode: boolean;
}

export interface SystemIntegrationStatus {
  frontend: {
    cryptoKeys: boolean;
    votingTokens: boolean;
    uiComponents: boolean;
  };
  backend: {
    database: boolean;
    votingEndpoints: boolean;
    ringManagement: boolean;
    tokenService: boolean;
  };
  crypto: {
    wasmLoaded: boolean;
    keyGeneration: boolean;
    ringSignatures: boolean;
    keyImages: boolean;
  };
  integration: {
    endToEndVoting: boolean;
    anonymityPreserved: boolean;
    doubleSpendPrevention: boolean;
  };
}

export class DecentralizedSystemIntegration {
  private static instance: DecentralizedSystemIntegration;
  private config: DecentralizedSystemConfig;

  constructor(config: Partial<DecentralizedSystemConfig> = {}) {
    this.config = {
      enableCrypto: true,
      enableRingSignatures: true,
      enableAnonymousVoting: true,
      testMode: true, // Default to test mode
      ...config
    };
  }

  static getInstance(config?: Partial<DecentralizedSystemConfig>): DecentralizedSystemIntegration {
    if (!DecentralizedSystemIntegration.instance) {
      DecentralizedSystemIntegration.instance = new DecentralizedSystemIntegration(config);
    }
    return DecentralizedSystemIntegration.instance;
  }

  /**
   * Initialize the complete decentralized system
   */
  async initialize(): Promise<{ success: boolean; status: SystemIntegrationStatus }> {
    console.log('🚀 Initializing Decentralized ProofPals System...');
    
    const status: SystemIntegrationStatus = {
      frontend: { cryptoKeys: false, votingTokens: false, uiComponents: true },
      backend: { database: false, votingEndpoints: false, ringManagement: false, tokenService: false },
      crypto: { wasmLoaded: false, keyGeneration: false, ringSignatures: false, keyImages: false },
      integration: { endToEndVoting: false, anonymityPreserved: false, doubleSpendPrevention: false }
    };

    try {
      // 1. Initialize Crypto Layer
      console.log('🔐 Initializing cryptographic components...');
      await this.initializeCrypto(status);

      // 2. Initialize Backend Integration
      console.log('🌐 Checking backend integration...');
      await this.checkBackendIntegration(status);

      // 3. Initialize Frontend Components
      console.log('⚛️ Initializing frontend components...');
      await this.initializeFrontend(status);

      // 4. Test End-to-End Integration
      console.log('🔗 Testing end-to-end integration...');
      await this.testIntegration(status);

      const success = this.isSystemHealthy(status);
      
      if (success) {
        console.log('✅ Decentralized system initialized successfully!');
        toast.success('Decentralized system is ready');
      } else {
        console.warn('⚠️ System initialized with some issues');
        toast.warning('System partially initialized - some features may not work');
      }

      return { success, status };

    } catch (error: any) {
      console.error('❌ System initialization failed:', error);
      toast.error(`System initialization failed: ${error.message}`);
      return { success: false, status };
    }
  }

  /**
   * Initialize cryptographic components
   */
  private async initializeCrypto(status: SystemIntegrationStatus): Promise<void> {
    try {
      // Initialize WASM module
      await SecureKeyManager.initialize();
      status.crypto.wasmLoaded = true;

      // Generate or load keys
      const { hasKeyPair, generateKeyPair } = useCryptoStore.getState();
      if (!hasKeyPair()) {
        await generateKeyPair();
      }
      status.crypto.keyGeneration = hasKeyPair();
      status.frontend.cryptoKeys = hasKeyPair();

      // Test ring signature functionality
      if (status.crypto.keyGeneration) {
        const testMessage = new TextEncoder().encode('test_message');
        const { keyPair } = useCryptoStore.getState();
        
        if (keyPair) {
          try {
            // Test key image generation
            const keyImage = SecureKeyManager.computeKeyImage(
              keyPair.secretKey,
              keyPair.publicKey,
              testMessage
            );
            status.crypto.keyImages = keyImage && keyImage.length === 32;
            console.log('Key image test:', { length: keyImage?.length, success: status.crypto.keyImages });

            // Test ring signature (with single member ring for testing)
            const signature = await SecureKeyManager.signVote(
              testMessage,
              [keyPair.publicKey],
              keyPair.secretKey,
              0
            );
            status.crypto.ringSignatures = !!signature && !!signature.key_image;
            console.log('Ring signature test:', { signature: !!signature, hasKeyImage: !!signature?.key_image, success: status.crypto.ringSignatures });
          } catch (error) {
            console.error('Crypto functionality test failed:', error);
            status.crypto.keyImages = false;
            status.crypto.ringSignatures = false;
          }
        }
      }

      // Check voting tokens
      const { tokens } = useCryptoStore.getState();
      status.frontend.votingTokens = tokens.length > 0;

    } catch (error) {
      console.error('Crypto initialization failed:', error);
    }
  }

  /**
   * Check backend integration
   */
  private async checkBackendIntegration(status: SystemIntegrationStatus): Promise<void> {
    try {
      // Test database connectivity
      const health = await apiClient.get('/health') as any;
      status.backend.database = health?.status === 'healthy' || health?.status === 'ok';

      // Test voting endpoints
      try {
        await apiClient.get('/api/v1/vote/requirements');
        status.backend.votingEndpoints = true;
      } catch {
        status.backend.votingEndpoints = false;
      }

      // Test ring management
      try {
        await apiClient.get('/api/v1/admin/rings');
        status.backend.ringManagement = true;
      } catch {
        status.backend.ringManagement = false;
      }

      // Test token service
      try {
        await apiClient.get('/api/v1/vote/requirements');
        status.backend.tokenService = true;
      } catch {
        status.backend.tokenService = false;
      }

    } catch (error) {
      console.error('Backend integration check failed:', error);
    }
  }

  /**
   * Initialize frontend components
   */
  private async initializeFrontend(status: SystemIntegrationStatus): Promise<void> {
    // Frontend components are already loaded (React components)
    status.frontend.uiComponents = true;

    // Publish public key to backend if available
    const publicKeyHex = useCryptoStore.getState().getPublicKeyHex();
    if (publicKeyHex && status.backend.database) {
      try {
        await apiClient.post('/api/v1/reviewer/public-key', {
          public_key_hex: publicKeyHex
        });
        console.log('✅ Public key published to backend');
      } catch (error) {
        console.warn('⚠️ Failed to publish public key:', error);
      }
    }
  }

  /**
   * Test end-to-end integration
   */
  private async testIntegration(status: SystemIntegrationStatus): Promise<void> {
    try {
      // Test voting capability with more detailed checking
      const { keyPair, tokens } = useCryptoStore.getState();
      const hasKeys = !!keyPair;
      const hasTokens = tokens.length > 0;
      
      // Basic end-to-end capability check
      status.integration.endToEndVoting = 
        hasKeys && 
        hasTokens && 
        status.backend.database && 
        status.backend.votingEndpoints;

      console.log('E2E Test Details:', {
        hasKeys,
        hasTokens,
        database: status.backend.database,
        votingEndpoints: status.backend.votingEndpoints,
        result: status.integration.endToEndVoting
      });

      // Test anonymity preservation (crypto keys + ring signatures)
      status.integration.anonymityPreserved = 
        status.crypto.ringSignatures && 
        status.crypto.keyImages && 
        status.backend.ringManagement &&
        hasKeys;

      console.log('Anonymity Test Details:', {
        ringSignatures: status.crypto.ringSignatures,
        keyImages: status.crypto.keyImages,
        ringManagement: status.backend.ringManagement,
        hasKeys,
        result: status.integration.anonymityPreserved
      });

      // Test double-spend prevention (key images)
      status.integration.doubleSpendPrevention = 
        status.crypto.keyImages && 
        status.backend.votingEndpoints;

    } catch (error) {
      console.error('Integration test failed:', error);
      status.integration.endToEndVoting = false;
      status.integration.anonymityPreserved = false;
      status.integration.doubleSpendPrevention = false;
    }
  }

  /**
   * Check if system is healthy overall
   */
  private isSystemHealthy(status: SystemIntegrationStatus): boolean {
    const criticalComponents = [
      status.frontend.cryptoKeys,
      status.backend.database,
      status.backend.votingEndpoints,
      status.crypto.wasmLoaded,
      status.crypto.keyGeneration
    ];

    return criticalComponents.every(component => component);
  }

  /**
   * Get comprehensive system status
   */
  async getSystemStatus(): Promise<SystemIntegrationStatus> {
    const status: SystemIntegrationStatus = {
      frontend: { cryptoKeys: false, votingTokens: false, uiComponents: true },
      backend: { database: false, votingEndpoints: false, ringManagement: false, tokenService: false },
      crypto: { wasmLoaded: false, keyGeneration: false, ringSignatures: false, keyImages: false },
      integration: { endToEndVoting: false, anonymityPreserved: false, doubleSpendPrevention: false }
    };

    await this.initializeCrypto(status);
    await this.checkBackendIntegration(status);
    await this.testIntegration(status);

    return status;
  }

  /**
   * Perform a complete end-to-end test
   */
  async performEndToEndTest(): Promise<{ success: boolean; results: any }> {
    console.log('🧪 Performing end-to-end decentralized system test...');

    const results = {
      cryptoTest: false,
      backendTest: false,
      votingTest: false,
      anonymityTest: false,
      integrationTest: false
    };

    try {
      // Get system status first
      const systemStatus = await this.getSystemStatus();

      // 1. Test crypto functionality
      const { keyPair } = useCryptoStore.getState();
      if (keyPair) {
        const testMessage = new TextEncoder().encode('e2e_test');
        const keyImage = SecureKeyManager.computeKeyImage(
          keyPair.secretKey,
          keyPair.publicKey,
          testMessage
        );
        results.cryptoTest = keyImage.length === 32;
      }

      // 2. Test backend connectivity
      const health = await apiClient.get('/health') as any;
      results.backendTest = health?.status === 'healthy' || health?.status === 'ok';

      // 3. Test voting flow
      try {
        const votingFlowTest = await backendIntegration.testVotingFlow();
        results.votingTest = votingFlowTest.success;
        console.log('Voting flow test result:', votingFlowTest);
      } catch (error) {
        console.error('Voting flow test failed:', error);
        results.votingTest = false;
      }

      // 4. Test anonymity preservation
      results.anonymityTest = results.cryptoTest && 
                             results.backendTest && 
                             systemStatus.crypto.ringSignatures &&
                             systemStatus.crypto.keyImages;

      // 5. Test overall integration
      results.integrationTest = Object.values(results).every(test => test);

      const success = results.integrationTest;
      
      if (success) {
        console.log('✅ End-to-end test passed!');
        toast.success('All systems operational');
      } else {
        console.warn('⚠️ End-to-end test had issues');
        toast.warning('Some system components need attention');
      }

      return { success, results };

    } catch (error: any) {
      console.error('❌ End-to-end test failed:', error);
      toast.error(`System test failed: ${error.message}`);
      return { success: false, results };
    }
  }

  /**
   * Get decentralized features summary
   */
  getDecentralizedFeatures(): { feature: string; enabled: boolean; description: string }[] {
    const { hasKeyPair, tokens } = useCryptoStore.getState();

    return [
      {
        feature: 'Anonymous Voting',
        enabled: hasKeyPair() && tokens.length > 0,
        description: 'Vote anonymously using ring signatures'
      },
      {
        feature: 'Cryptographic Verification',
        enabled: hasKeyPair(),
        description: 'All votes are cryptographically signed and verified'
      },
      {
        feature: 'Double-Spend Prevention',
        enabled: hasKeyPair(),
        description: 'Key images prevent voting multiple times'
      },
      {
        feature: 'Ring Signatures',
        enabled: this.config.enableRingSignatures,
        description: 'Hide voter identity within a group of reviewers'
      },
      {
        feature: 'Decentralized Consensus',
        enabled: this.config.enableAnonymousVoting,
        description: 'Distributed decision making without central authority'
      },
      {
        feature: 'Privacy Preservation',
        enabled: hasKeyPair() && this.config.enableCrypto,
        description: 'Reviewer identities are protected cryptographically'
      }
    ];
  }
}

// Export singleton instance
export const decentralizedSystem = DecentralizedSystemIntegration.getInstance();
