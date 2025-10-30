// src/features/voting/hooks/useVote.ts
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { votingService, VotePayload } from '@/lib/services/votingService';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { toast } from 'sonner';

export function useVote() {
  const queryClient = useQueryClient();
  const { hasKeyPair } = useCryptoStore();

  return useMutation({
    mutationFn: async (payload: VotePayload) => {
      console.log('Vote payload received:', payload);
      
      // Check if we can vote
      const { canVote, reason } = await votingService.canVote();
      if (!canVote) {
        throw new Error(reason || 'Cannot vote at this time');
      }

      // Use simple voting for development/testing
      console.log('Submitting simple vote...');
      return await votingService.submitSimpleVote(payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submissions'] });
      queryClient.invalidateQueries({ queryKey: ['approved-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['submission'] });
      queryClient.invalidateQueries({ queryKey: ['admin-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['admin-stats'] });
      queryClient.invalidateQueries({ queryKey: ['system-status'] });
      queryClient.invalidateQueries({ queryKey: ['escalations'] });
      toast.success('Vote submitted successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to submit vote');
    },
  });
}