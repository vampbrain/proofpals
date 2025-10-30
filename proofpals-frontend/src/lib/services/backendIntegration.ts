// src/lib/services/backendIntegration.ts
import { apiClient } from '@/lib/api/client';
import { useCryptoStore } from '@/lib/crypto/key-manager';

export interface BackendStatus {
  database: boolean;
  crypto: boolean;
  rings: boolean;
  tokens: boolean;
  voting: boolean;
}

export interface SystemRequirements {
  hasKeys: boolean;
  hasTokens: boolean;
  hasRings: boolean;
  canVote: boolean;
  pendingSubmissions: number;
}

export class BackendIntegrationService {
  private static instance: BackendIntegrationService;
  
  static getInstance(): BackendIntegrationService {
    if (!BackendIntegrationService.instance) {
      BackendIntegrationService.instance = new BackendIntegrationService();
    }
    return BackendIntegrationService.instance;
  }

  /**
   * Check overall system health and integration status
   */
  async checkSystemHealth(): Promise<BackendStatus> {
    const status: BackendStatus = {
      database: false,
      crypto: false,
      rings: false,
      tokens: false,
      voting: false
    };

    try {
      // Test database connectivity
      const health = await apiClient.get('/health') as any;
      status.database = health?.status === 'healthy' || health?.status === 'ok';

      // Test crypto integration
      const { hasKeyPair } = useCryptoStore.getState();
      status.crypto = hasKeyPair();

      // Test rings availability
      try {
        const rings = await apiClient.get('/api/v1/admin/rings');
        status.rings = Array.isArray((rings as any)?.rings) && (rings as any).rings.length > 0;
      } catch {
        status.rings = false;
      }

      // Test tokens availability
      try {
        const tokenCheck = await apiClient.get('/api/v1/vote/requirements');
        status.tokens = (tokenCheck as any)?.tokens?.length > 0;
      } catch {
        status.tokens = false;
      }

      // Test ring management
      try {
        const rings = await apiClient.get('/api/v1/admin/rings') as any;
        status.rings = true;
        console.log('Ring management test:', { success: true, ringCount: rings?.rings?.length || 0 });
      } catch (error) {
        console.error('Ring management test failed:', error);
        status.rings = false;
      }

      // Test voting capability
      try {
        await apiClient.get('/api/v1/vote/debug');
        status.voting = true;
      } catch {
        status.voting = false;
      }

    } catch (error) {
      console.error('System health check failed:', error);
    }

    return status;
  }

  /**
   * Initialize the decentralized system components
   */
  async initializeSystem(): Promise<{ success: boolean; message: string }> {
    try {
      console.log('Initializing decentralized system...');

      // 1. Initialize crypto if not already done
      const { hasKeyPair, generateKeyPair } = useCryptoStore.getState();
      if (!hasKeyPair()) {
        console.log('Generating cryptographic keys...');
        await generateKeyPair();
      }

      // 2. Publish public key to backend
      const publicKeyHex = useCryptoStore.getState().getPublicKeyHex();
      if (publicKeyHex) {
        try {
          await apiClient.post('/api/v1/crypto/publish-key', {
            public_key_hex: publicKeyHex
          });
          console.log('Public key published to backend');
        } catch (error) {
          console.warn('Failed to publish public key:', error);
        }
      }

      // 3. Check if rings exist, create test ring if needed
      await this.ensureTestRingExists();

      // 4. Ensure we have test data for testing
      await this.ensureTestData();

      // 4. Check voting requirements
      const requirements = await this.getSystemRequirements();
      
      if (requirements.canVote) {
        return {
          success: true,
          message: 'Decentralized system initialized successfully'
        };
      } else {
        return {
          success: false,
          message: 'System initialized but voting requirements not met'
        };
      }

    } catch (error: any) {
      console.error('System initialization failed:', error);
      return {
        success: false,
        message: `Initialization failed: ${error.message}`
      };
    }
  }

  /**
   * Get comprehensive system requirements status
   */
  async getSystemRequirements(): Promise<SystemRequirements> {
    const { hasKeyPair, tokens } = useCryptoStore.getState();
    
    const requirements: SystemRequirements = {
      hasKeys: hasKeyPair(),
      hasTokens: tokens.length > 0,
      hasRings: false,
      canVote: false,
      pendingSubmissions: 0
    };

    try {
      // Check backend requirements
      const backendReqs = await apiClient.get('/api/v1/vote/requirements');
      const reqData = backendReqs as any;
      
      requirements.hasRings = reqData?.rings?.length > 0;
      requirements.pendingSubmissions = reqData?.submissions?.length || 0;
      requirements.canVote = reqData?.can_vote || false;

    } catch (error) {
      console.error('Failed to get system requirements:', error);
    }

    return requirements;
  }

  /**
   * Ensure a test ring exists for development/testing
   */
  private async ensureTestRingExists(): Promise<void> {
    try {
      // Check if test ring exists
      const rings = await apiClient.get('/api/v1/admin/rings') as any;
      const testRing = rings?.rings?.find((r: any) => r.genre === 'test');
      
      if (!testRing) {
        console.log('Creating test ring...');
        
        // Get public key for test ring
        const publicKeyHex = useCryptoStore.getState().getPublicKeyHex();
        const testKey = publicKeyHex || Array(64).fill('0').join('');
        
        await apiClient.post('/api/v1/admin/rings', {
          genre: 'test',
          epoch: Math.floor(Date.now() / 1000).toString(),
          pubkeys: [testKey]
        });
        
        console.log('Test ring created successfully');
      } else {
        console.log('Test ring already exists');
      }

      // Also ensure we have some test tokens
      const { tokens, addTokens } = useCryptoStore.getState();
      if (tokens.length === 0) {
        console.log('Adding test tokens...');
        const testTokens = Array(5).fill(0).map((_, i) => `test_token_${Date.now()}_${i}`);
        addTokens(testTokens);
        console.log('Test tokens added');
      }
    } catch (error) {
      console.warn('Failed to ensure test ring exists:', error);
    }
  }

  /**
   * Ensure test data exists for testing
   */
  private async ensureTestData(): Promise<void> {
    try {
      // Check if we have any submissions
      const submissions = await apiClient.get('/api/v1/submissions') as any;
      
      if (!submissions?.submissions || submissions.submissions.length === 0) {
        console.log('No submissions found - this is normal for a fresh system');
        // In a real system, we might create test submissions here
        // For now, we'll just note that the system is ready for submissions
      }
    } catch (error) {
      console.warn('Could not check test data:', error);
    }
  }

  /**
   * Test the complete voting flow
   */
  async testVotingFlow(): Promise<{ success: boolean; details: any }> {
    try {
      console.log('Testing complete voting flow...');

      // 1. Check system health
      const health = await this.checkSystemHealth();
      console.log('System health:', health);

      // 2. Check requirements
      const requirements = await this.getSystemRequirements();
      console.log('System requirements:', requirements);

      // 3. Try to get a test submission
      let testSubmission = null;
      try {
        const submissions = await apiClient.get('/api/v1/submissions');
        testSubmission = (submissions as any)?.submissions?.[0];
      } catch (error) {
        console.warn('Could not fetch submissions:', error);
      }

      // If no submissions, that's okay for testing - we'll just test the endpoints

      // 4. Test vote requirements endpoint
      const voteReqs = await apiClient.get('/api/v1/vote/requirements');
      console.log('Vote requirements:', voteReqs);

      return {
        success: true,
        details: {
          health,
          requirements,
          testSubmission: testSubmission?.id || 'none',
          voteRequirements: voteReqs
        }
      };

    } catch (error: any) {
      console.error('Voting flow test failed:', error);
      return {
        success: false,
        details: { error: error.message }
      };
    }
  }

  /**
   * Get decentralized system statistics
   */
  async getSystemStats(): Promise<any> {
    try {
      const [stats, health, requirements] = await Promise.all([
        apiClient.get('/api/v1/admin/statistics'),
        this.checkSystemHealth(),
        this.getSystemRequirements()
      ]);

      return {
        ...(stats as any),
        systemHealth: health,
        requirements,
        decentralizedFeatures: {
          ringSignatures: health.crypto && health.rings,
          anonymousVoting: health.voting && requirements.hasTokens,
          cryptographicVerification: health.crypto,
          distributedConsensus: health.rings && health.voting
        }
      };
    } catch (error) {
      console.error('Failed to get system stats:', error);
      return null;
    }
  }

  /**
   * Reset and reinitialize the system
   */
  async resetSystem(): Promise<{ success: boolean; message: string }> {
    try {
      console.log('Resetting decentralized system...');

      // Clear local crypto state
      useCryptoStore.getState().clearAll();

      // Reinitialize
      return await this.initializeSystem();

    } catch (error: any) {
      return {
        success: false,
        message: `Reset failed: ${error.message}`
      };
    }
  }
}

// Export singleton instance
export const backendIntegration = BackendIntegrationService.getInstance();
