// src/pages/Reviewer/Dashboard.tsx
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Loader2, FileText, Clock, CheckCircle2, Plus } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { useCryptoStore } from '@/lib/crypto/key-manager';

// Component to show submission with vote status
function SubmissionItem({ submission }: { submission: any }) {
  const navigate = useNavigate();
  
  const { data: voteStatus } = useQuery({
    queryKey: ['vote-status', submission.id],
    queryFn: () => apiClient.get(`/api/v1/submissions/${submission.id}/vote-status`),
    staleTime: 30000, // Cache for 30 seconds
  });

  const hasVoted = (voteStatus as any)?.has_voted || false;
  const voteType = (voteStatus as any)?.vote_type;

  return (
    <div className="flex items-center justify-between border-b pb-4">
      <div>
        <p className="font-medium">Submission #{submission.id}</p>
        <p className="text-sm text-muted-foreground capitalize">
          {submission.genre} • {new Date(submission.created_at).toLocaleDateString()}
        </p>
        <p className="text-xs text-gray-500 truncate max-w-md mt-1">
          {submission.content_ref}
        </p>
      </div>
      <div className="flex items-center gap-2">
        {hasVoted ? (
          <Badge className={`${
            voteType === 'approve' ? 'bg-green-50 text-green-700 border border-green-200' :
            voteType === 'reject' ? 'bg-red-50 text-red-700 border border-red-200' :
            voteType === 'escalate' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
            'bg-blue-50 text-blue-700 border border-blue-200'
          }`}>
            Voted: {voteType}
          </Badge>
        ) : (
          <>
            <Badge className="bg-yellow-50 text-yellow-700 border border-yellow-200">
              Pending
            </Badge>
            <Button 
              size="sm" 
              onClick={() => navigate(`/review/${submission.id}`)}
              className="ml-2"
            >
              Review
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';

interface ReviewerStats {
  available_submissions: number;
  votes_cast: number;
  tokens_remaining: number;
}

export function ReviewerDashboard() {
  const navigate = useNavigate();
  const { tokens, getPublicKeyHex } = useCryptoStore();
  const publicKeyHex = getPublicKeyHex();
  
  const { data: stats, isLoading } = useQuery<ReviewerStats>({
    queryKey: ['reviewer-stats'],
    queryFn: () => apiClient.get('/api/v1/reviewer/stats'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: nextSubmission } = useQuery<any>({
    queryKey: ['next-submission'],
    queryFn: () => apiClient.get('/api/v1/reviewer/next'),
    enabled: tokens.length > 0,
  });

  const { data: availableSubmissions } = useQuery<any>({
    queryKey: ['reviewer-submissions'],
    queryFn: () => apiClient.get('/api/v1/reviewer/submissions'),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Navigation role="reviewer" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto max-w-6xl space-y-8 p-6">
          {/* Page Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold">Reviewer Dashboard</h1>
              <p className="text-muted-foreground">
                Review submissions anonymously and help maintain quality
              </p>
            </div>
            <Button onClick={() => navigate('/reviewer/upload')}>
              <Plus className="mr-2 h-4 w-4" />
              Submit Content
            </Button>
          </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Available Reviews</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.available_submissions || 0}</div>
            <p className="text-xs text-muted-foreground">
              Submissions waiting for review
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Votes Cast</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.votes_cast || 0}</div>
            <p className="text-xs text-muted-foreground">
              This epoch
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Tokens Remaining</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tokens.length}</div>
            <p className="text-xs text-muted-foreground">
              Available for voting
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Token Warning */}
      {tokens.length === 0 && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardHeader>
            <CardTitle className="text-yellow-800">No Tokens Available</CardTitle>
            <CardDescription className="text-yellow-700">
              You need to present your credential to receive epoch tokens before voting.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button 
              onClick={() => navigate('/reviewer/tokens')}
              className="bg-yellow-600 hover:bg-yellow-700"
            >
              Get Epoch Tokens
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Quick Review Section */}
      {nextSubmission && tokens.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Next Review</CardTitle>
                <CardDescription>
                  Submission #{nextSubmission.id} in {nextSubmission.genre}
                </CardDescription>
              </div>
              <Badge variant="secondary">{nextSubmission.genre}</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              A new submission is ready for your review
            </p>
            <Button 
              onClick={() => navigate(`/review/${nextSubmission.id}`)}
              size="lg"
              className="w-full"
            >
              Start Review
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Available Submissions for Review */}
      <Card>
        <CardHeader>
          <CardTitle>Available for Review</CardTitle>
          <CardDescription>Pending submissions waiting for your review</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {availableSubmissions && availableSubmissions.length > 0 ? (
              availableSubmissions.slice(0, 3).map((submission: any) => (
                <SubmissionItem key={submission.id} submission={submission} />
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <p>No submissions available for review</p>
                <p className="text-sm mt-1">Check back later for new content</p>
              </div>
            )}
            <div className="pt-2">
              <Button onClick={() => navigate('/reviewer/submissions')} variant="outline" className="w-full">
                View All Submissions
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Subtle Public Key Display */}
      {publicKeyHex && (
        <div className="mt-8 pt-4 border-t border-gray-100">
          <div className="text-xs text-gray-400 space-y-1">
            <div className="flex items-center justify-between">
              <span>Reviewer ID:</span>
              <span className="font-mono">{publicKeyHex.substring(0, 8)}...{publicKeyHex.substring(-8)}</span>
            </div>
          </div>
        </div>
      )}
        </main>
      </div>
    </div>
  );
}