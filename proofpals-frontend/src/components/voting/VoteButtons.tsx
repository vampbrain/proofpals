// src/components/voting/VoteButtons.tsx
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { AnonConfirmationModal } from './AnonConfirmationModal';
import { ThumbsUp, AlertTriangle, ThumbsDown, Flag } from 'lucide-react';
import { cn } from '@/lib/utils';

export type VoteType = 'approve' | 'escalate' | 'reject' | 'flag';

interface VoteButtonsProps {
  submissionId: number;
  onVote: (voteType: VoteType) => Promise<void>;
  disabled?: boolean;
  className?: string;
}

export function VoteButtons({ 
  submissionId, 
  onVote, 
  disabled = false,
  className 
}: VoteButtonsProps) {
  const [selectedVote, setSelectedVote] = useState<VoteType | null>(null);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [isVoting, setIsVoting] = useState(false);

  const handleVoteClick = (voteType: VoteType) => {
    setSelectedVote(voteType);
    setShowConfirmation(true);
  };

  const handleConfirm = async () => {
    if (!selectedVote) return;
    
    setIsVoting(true);
    try {
      await onVote(selectedVote);
      setShowConfirmation(false);
    } catch (error) {
      // Error handling will be in parent component
      throw error;
    } finally {
      setIsVoting(false);
    }
  };

  const voteOptions = [
    {
      type: 'approve' as VoteType,
      label: 'Approve',
      description: 'This content meets quality standards',
      icon: ThumbsUp,
      className: 'bg-green-500 hover:bg-green-600 text-white',
    },
    {
      type: 'escalate' as VoteType,
      label: 'Escalate',
      description: 'Needs expert review',
      icon: AlertTriangle,
      className: 'bg-yellow-500 hover:bg-yellow-600 text-white',
    },
    {
      type: 'reject' as VoteType,
      label: 'Reject',
      description: 'Does not meet standards',
      icon: ThumbsDown,
      className: 'bg-red-500 hover:bg-red-600 text-white',
    },
    {
      type: 'flag' as VoteType,
      label: 'Flag',
      description: 'Potentially harmful content',
      icon: Flag,
      className: 'bg-red-700 hover:bg-red-800 text-white',
    },
  ];

  return (
    <>
      <div className={cn('grid grid-cols-2 gap-4', className)}>
        {voteOptions.map(({ type, label, description, icon: Icon, className }) => (
          <Button
            key={type}
            size="lg"
            disabled={disabled || isVoting}
            onClick={() => handleVoteClick(type)}
            className={cn('h-24 flex-col gap-2', className)}
          >
            <Icon className="h-6 w-6" />
            <div className="flex flex-col">
              <span className="font-bold">{label}</span>
              <span className="text-xs opacity-90">{description}</span>
            </div>
          </Button>
        ))}
      </div>

      <AnonConfirmationModal
        open={showConfirmation}
        onOpenChange={setShowConfirmation}
        voteType={selectedVote}
        onConfirm={handleConfirm}
        isLoading={isVoting}
      />
    </>
  );
}