// src/components/voting/AnonConfirmationModal.tsx
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Shield, Info } from 'lucide-react';
import { VoteType } from './VoteButtons';

interface AnonConfirmationModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  voteType: VoteType | null;
  onConfirm: () => void;
  isLoading: boolean;
}

export function AnonConfirmationModal({
  open,
  onOpenChange,
  voteType,
  onConfirm,
  isLoading,
}: AnonConfirmationModalProps) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-green-500" />
            Confirm Anonymous Vote
          </AlertDialogTitle>
          <AlertDialogDescription className="space-y-4">
            <p>
              You are about to submit an <strong>anonymous {voteType}</strong> vote.
            </p>
            
            <div className="rounded-lg bg-blue-50 p-4 text-sm text-blue-900">
              <div className="flex gap-2">
                <Info className="h-5 w-5 flex-shrink-0" />
                <div className="space-y-2">
                  <p className="font-semibold">Privacy Protection:</p>
                  <ul className="list-inside list-disc space-y-1">
                    <li>Your identity will remain anonymous</li>
                    <li>Vote is cryptographically signed</li>
                    <li>You cannot vote twice on the same submission</li>
                    <li>One token will be consumed</li>
                  </ul>
                </div>
              </div>
            </div>

            <p className="text-sm font-semibold">
              Once submitted, this vote cannot be changed. Proceed?
            </p>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isLoading} onClick={() => onOpenChange(false)}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={isLoading}
            className="bg-green-600 hover:bg-green-700"
          >
            {isLoading ? 'Submitting...' : 'Confirm & Submit'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}