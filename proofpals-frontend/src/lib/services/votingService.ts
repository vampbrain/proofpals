// src/lib/services/votingService.ts
import { apiClient } from '@/lib/api/client';
import { SecureKeyManager, useCryptoStore } from '@/lib/crypto/key-manager';

export interface VotePayload {
  submission_id: number;
  vote_type: 'approve' | 'reject' | 'escalate' | 'flag';
  ring_id?: number;
}

export interface RingSignatureVote {
  submission_id: number;
  ring_id: number;
  signature_blob: string;
  vote_type: string;
  token_id: string;
  message: string;
  key_image: string;
}

export class VotingService {
  private static instance: VotingService;
  
  static getInstance(): VotingService {
    if (!VotingService.instance) {
      VotingService.instance = new VotingService();
    }
    return VotingService.instance;
  }

  /**
   * Submit a vote with full cryptographic verification
   */
  async submitVote(payload: VotePayload): Promise<any> {
    try {
      // 1. Check prerequisites
      const { keyPair, tokens } = useCryptoStore.getState();
      
      if (!keyPair) {
        throw new Error('No cryptographic keys available. Please generate keys first.');
      }

      if (tokens.length === 0) {
        throw new Error('No voting tokens available. Please obtain tokens first.');
      }

      // 2. Get available ring for the submission
      const ring = await this.getRingForSubmission(payload.submission_id);
      if (!ring) {
        throw new Error('No suitable ring found for this submission');
      }

      // 3. Create canonical message for signing
      const message = await SecureKeyManager.createCanonicalMessage({
        submissionId: payload.submission_id.toString(),
        genre: ring.genre || 'general',
        voteType: payload.vote_type,
        epoch: ring.epoch || Math.floor(Date.now() / 1000),
        nonce: Math.random().toString(36).substring(2, 15)
      });

      // 4. Find signer index in ring
      const publicKeyHex = Array.from(keyPair.publicKey)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      
      // Use the correct property name from backend
      const ringPublicKeys = ring.public_keys || ring.pubkeys || [];
      console.log('🔑 User public key:', publicKeyHex);
      console.log('🔑 Ring public keys:', ringPublicKeys);
      
      const signerIndex = ringPublicKeys.findIndex((pk: string) => pk === publicKeyHex);
      if (signerIndex === -1) {
        console.error('❌ Public key not found in ring');
        console.error('User key:', publicKeyHex);
        console.error('Ring keys:', ringPublicKeys);
        throw new Error('Your public key is not in the ring for this submission');
      }

      console.log('✅ Found user key at index:', signerIndex);

      // 5. Convert ring public keys to Uint8Array format
      const ringKeys = ringPublicKeys.map((pk: string) => 
        new Uint8Array(pk.match(/.{2}/g)?.map(byte => parseInt(byte, 16)) || [])
      );

      // 6. Generate ring signature
      const signature = await SecureKeyManager.signVote(
        message,
        ringKeys,
        keyPair.secretKey,
        signerIndex
      );

      // 7. Compute key image for double-spend prevention
      const keyImage = SecureKeyManager.computeKeyImage(
        keyPair.secretKey,
        keyPair.publicKey,
        message
      );

      // 8. Prepare vote data
      const voteData: RingSignatureVote = {
        submission_id: payload.submission_id,
        ring_id: ring.id,
        signature_blob: JSON.stringify(signature),
        vote_type: payload.vote_type,
        token_id: tokens[0], // Use first available token
        message: Array.from(message).map(b => b.toString(16).padStart(2, '0')).join(''),
        key_image: Array.from(keyImage).map(b => b.toString(16).padStart(2, '0')).join('')
      };

      // 9. Submit to backend
      const result = await apiClient.post('/api/v1/vote', voteData);

      // 10. Consume token locally
      useCryptoStore.getState().consumeToken(tokens[0]);

      return result;

    } catch (error: any) {
      console.error('Vote submission failed:', error);
      throw error;
    }
  }

  /**
   * Submit a test vote (bypasses crypto verification)
   */
  async submitTestVote(payload: VotePayload): Promise<any> {
    try {
      const { tokens } = useCryptoStore.getState();
      const token_id = tokens.length > 0 ? tokens[0] : `test_token_${Date.now()}`;
      
      // Get or create a test ring
      const ring_id = payload.ring_id || await this.getOrCreateTestRing();
      
      // Create test message
      const testMessage = `vote_${payload.submission_id}_${payload.vote_type}_${Date.now()}`;
      const message = Array.from(new TextEncoder().encode(testMessage))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      const voteData = {
        submission_id: payload.submission_id,
        ring_id: ring_id,
        signature_blob: JSON.stringify({
          key_image: Array(32).fill(0).map(() => Math.floor(Math.random() * 256)),
          c1: Array(32).fill(0).map(() => Math.floor(Math.random() * 256)),
          responses: [Array(32).fill(0).map(() => Math.floor(Math.random() * 256))],
          ringLength: 1,
          signerIndex: 0
        }),
        vote_type: payload.vote_type,
        token_id,
        message,
      };

      const result = await apiClient.post('/api/v1/vote/test', voteData);

      // Consume token if available
      if (tokens.length > 0) {
        useCryptoStore.getState().consumeToken(token_id);
      }

      return result;

    } catch (error: any) {
      console.error('Test vote submission failed:', error);
      throw error;
    }
  }

  /**
   * Get suitable ring for a submission
   */
  private async getRingForSubmission(submissionId: number): Promise<any> {
    try {
      // Get submission details
      const submission = await apiClient.get(`/api/v1/submissions/${submissionId}`) as any;
      console.log('📄 Submission details:', submission);
      
      // Get rings for the submission's genre
      const ringsResponse = await apiClient.get('/api/v1/rings', {
        params: { genre: submission.genre, active: true }
      }) as any;
      
      console.log('🔍 Available rings:', ringsResponse);
      
      const rings = ringsResponse.rings || [];
      const suitableRing = rings.find((ring: any) => {
        const ringKeys = ring.public_keys || ring.pubkeys || [];
        return ring.genre === submission.genre && 
               ring.active && 
               ringKeys && 
               ringKeys.length > 0;
      });
      
      if (!suitableRing) {
        console.warn(`No suitable ring found for genre: ${submission.genre}`);
        return null;
      }
      
      console.log('✅ Found suitable ring:', suitableRing);
      return suitableRing;
    } catch (error) {
      console.error('Failed to get ring for submission:', error);
      return null;
    }
  }

/**
* Get or create a test ring for development
*/
private async getOrCreateTestRing(): Promise<number> {
try {
// Try to get existing rings
const ringsResponse = await apiClient.get('/api/v1/rings') as any;
const rings = ringsResponse.rings || [];
  
if (rings.length > 0) {
return rings[0].id;
}

// Create test ring if none exists
const { keyPair } = useCryptoStore.getState();
const publicKeyHex = keyPair ? 
Array.from(keyPair.publicKey).map(b => b.toString(16).padStart(2, '0')).join('') :
'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

const newRing = await apiClient.post('/api/v1/rings', {
genre: 'test',
epoch: Math.floor(Date.now() / 1000),
pubkeys: [publicKeyHex]
}) as any;

return newRing.ring_id || newRing.id || 1;
} catch (error) {
console.error('Failed to get or create test ring:', error);
return 1; // Fallback ring ID
}
}

/**
* Submit vote with fallback to test mode
*/
async submitVoteWithFallback(payload: VotePayload): Promise<any> {
try {
// Try test vote first for development
console.log('🗳️ Attempting to submit vote:', payload);
return await this.submitTestVote(payload);
} catch (testError: any) {
console.warn('Test vote failed, trying normal vote:', testError.message);
  
// Fallback to normal vote
try {
return await this.submitVote(payload);
} catch (normalError: any) {
console.error('Normal vote also failed:', normalError.message);
throw new Error(`Both test and normal voting failed: ${testError.message}`);
}
}
}

  /**
   * Submit a simple vote (for testing)
   */
  async submitSimpleVote(payload: VotePayload): Promise<any> {
    try {
      console.log('🗳️ Submitting simple vote:', payload);
      
      // Get any available ring
      const ringsResponse = await apiClient.get('/api/v1/rings') as any;
      const rings = ringsResponse.rings || [];
      
      if (rings.length === 0) {
        throw new Error('No rings available for voting');
      }
      
      const ring = rings[0]; // Use first available ring
      const { tokens } = useCryptoStore.getState();
      const token_id = tokens.length > 0 ? tokens[0] : `simple_token_${Date.now()}`;
      
      const voteData = {
        submission_id: payload.submission_id,
        ring_id: ring.id,
        signature_blob: JSON.stringify({
          test: true,
          timestamp: Date.now()
        }),
        vote_type: payload.vote_type,
        token_id,
        message: `simple_vote_${payload.submission_id}_${Date.now()}`,
      };

      console.log('📤 Sending vote data:', voteData);
      const result = await apiClient.post('/api/v1/vote/test', voteData);
      
      // Consume token if available
      if (tokens.length > 0) {
        useCryptoStore.getState().consumeToken(token_id);
      }

      console.log('✅ Vote submitted successfully:', result);
      return result;

    } catch (error: any) {
      console.error('❌ Simple vote submission failed:', error);
      throw error;
    }
  }

  /**
   * Check if user can vote (simplified for testing)
   */
  async canVote(): Promise<{ canVote: boolean; reason?: string }> {
    try {
      // For development/testing, always allow voting
      return { canVote: true };
    } catch (error: any) {
      return { canVote: false, reason: 'Error checking vote eligibility' };
    }
  }

  /**
   * Get voting statistics and system status
   */
  async getVotingStats(): Promise<any> {
    try {
      return await apiClient.get('/api/v1/vote/stats');
    } catch (error: any) {
      return null;
    }
  }
}

// Export singleton instance
export const votingService = VotingService.getInstance();
