// src/pages/Reviewer/Review.tsx
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, ArrowLeft, Shield, Info, Key } from 'lucide-react';
import { VoteButtons } from '@/components/voting/VoteButtons';
import { useVote } from '@/features/voting/hooks/useVote';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { toast } from 'sonner';
import { ContentViewer } from '@/components/submission/ContentViewer';
import { useCryptoStore } from '@/lib/crypto/key-manager';

export function ReviewPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [isVoting, setIsVoting] = useState(false);
  const [canVote, setCanVote] = useState(false);
  const [isInitializingKeys, setIsInitializingKeys] = useState(false);
  const { hasKeyPair, generateKeyPair } = useCryptoStore();
  
  const { data: submission, isLoading } = useQuery<any>({
    queryKey: ['submission', id],
    queryFn: () => apiClient.get(API_ENDPOINTS.submission(Number(id))),
    enabled: !!id,
  });

  const voteMutation = useVote();
  const { tokens } = useCryptoStore();

  // Auto-initialize keypair if not present
  useEffect(() => {
    const initializeKeypair = async () => {
      if (!hasKeyPair()) {
        setIsInitializingKeys(true);
        try {
          await generateKeyPair();
          toast.success('Cryptographic keys initialized for secure voting');
        } catch (error: any) {
          toast.error('Failed to initialize keys: ' + (error.message || 'Unknown error'));
        } finally {
          setIsInitializingKeys(false);
        }
      }
    };

    initializeKeypair();
  }, [hasKeyPair, generateKeyPair]);

  const handleVote = async (voteType: string) => {
    if (!submission) return;
    
    setIsVoting(true);
    try {
      await voteMutation.mutateAsync({
        submission_id: submission.submission_id || submission.id,
        ring_id: submission.ring_id || 1, // Use ring 1 as default for testing
        vote_type: voteType,
      });
      
      toast.success('Vote submitted successfully!');
      navigate('/reviewer/dashboard');
    } catch (error: any) {
      console.error('Vote error:', error);
      toast.error(error.response?.data?.detail || error.message || 'Failed to submit vote');
    } finally {
      setIsVoting(false);
    }
  };

  if (isLoading || isInitializingKeys) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center space-y-4">
          <Loader2 className="h-8 w-8 animate-spin mx-auto" />
          <p className="text-sm text-muted-foreground">
            {isInitializingKeys ? 'Initializing secure keys...' : 'Loading submission...'}
          </p>
        </div>
      </div>
    );
  }

  if (!submission) {
    return (
      <div className="container mx-auto max-w-4xl p-6">
        <Alert variant="destructive">
          <AlertDescription>Submission not found</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-4xl space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          onClick={() => navigate('/reviewer/dashboard')}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Dashboard
        </Button>
        <Badge variant="secondary">{submission.genre}</Badge>
      </div>

      {/* Privacy Notice */}
      <Alert className="border-blue-200 bg-blue-50">
        <Shield className="h-4 w-4 text-blue-600" />
        <AlertDescription className="text-blue-900">
          Your vote is <strong>anonymous and cryptographically protected</strong>. 
          No one can link this vote to your identity.
        </AlertDescription>
      </Alert>

      {/* Content Card */}
      <Card>
        <CardHeader>
          <CardTitle>Review Submission #{submission.submission_id}</CardTitle>
          <CardDescription>
            Submitted {new Date(submission.created_at).toLocaleDateString()}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Content Display */}
          <div className="rounded-lg border bg-muted/50 p-6">
            <h3 className="mb-4 text-lg font-semibold">Content</h3>
            <div className="prose max-w-none">
              <div className="text-sm text-muted-foreground">
                Content Reference: {submission.content_ref}
              </div>
              <div className="mt-4">
                <ContentViewer contentRef={submission.content_ref} />
              </div>
            </div>
          </div>

          {/* Voting Guidelines */}
          <div className="rounded-lg border bg-blue-50 p-4">
            <div className="flex gap-2">
              <Info className="h-5 w-5 flex-shrink-0 text-blue-600" />
              <div className="space-y-2 text-sm text-blue-900">
                <div className="font-semibold">Voting Guidelines:</div>
                <ul className="list-inside list-disc space-y-1">
                  <li><strong>Approve:</strong> Content meets quality standards</li>
                  <li><strong>Escalate:</strong> Needs expert review or unclear</li>
                  <li><strong>Reject:</strong> Does not meet quality standards</li>
                  <li><strong>Flag:</strong> Potentially harmful or inappropriate</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Voting Section */}
      <Card>
        <CardHeader>
          <CardTitle>Cast Your Vote</CardTitle>
          <CardDescription>
            This action cannot be undone. Choose carefully.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4 text-sm text-muted-foreground">
            Remaining tokens: <span className="font-semibold">{tokens.length}</span>
          </div>
          {!canVote ? (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Please review the content above. When ready, click below to proceed to voting.
              </p>
              <Button onClick={() => setCanVote(true)} className="w-full">
                Start Review
              </Button>
            </div>
          ) : (
            <VoteButtons
              submissionId={submission.submission_id}
              onVote={handleVote}
              disabled={isVoting}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}