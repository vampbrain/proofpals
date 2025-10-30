// src/pages/Submitter/SubmissionResults.tsx
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, ArrowLeft, CheckCircle, XCircle, AlertTriangle, Flag } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { Progress } from '@/components/ui/progress';
import { useNavigate } from 'react-router-dom';

export function SubmissionResultsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  
  const { data: tally, isLoading } = useQuery<any>({
    queryKey: ['submission-results', id],
    queryFn: () => apiClient.get(API_ENDPOINTS.tally(Number(id))),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  if (!tally) {
    return (
      <div className="container mx-auto max-w-4xl p-6">
        <Alert variant="destructive">
          <AlertDescription>Submission results not found</AlertDescription>
        </Alert>
      </div>
    );
  }

  // Calculate percentages for the progress bars
  const counts = tally.counts || { approve: 0, reject: 0, escalate: 0, flag: 0 };
  const totalVotes = tally.total_votes ?? (counts.approve + counts.reject + counts.escalate + counts.flag);
  
  const approvePercent = totalVotes > 0 ? (counts.approve / totalVotes) * 100 : 0;
  const rejectPercent = totalVotes > 0 ? (counts.reject / totalVotes) * 100 : 0;
  const escalatePercent = totalVotes > 0 ? (counts.escalate / totalVotes) * 100 : 0;
  const flagPercent = totalVotes > 0 ? (counts.flag / totalVotes) * 100 : 0;

  // Determine the decision based on the highest vote count
  const getDecision = () => {
    if (totalVotes === 0) return 'Pending';
    
    const localCounts = [
      { type: 'approved', count: counts.approve },
      { type: 'rejected', count: counts.reject },
      { type: 'escalated', count: counts.escalate },
      { type: 'flagged', count: counts.flag }
    ];
    
    localCounts.sort((a, b) => b.count - a.count);
    return localCounts[0].type.charAt(0).toUpperCase() + localCounts[0].type.slice(1);
  };

  const getDecisionIcon = () => {
    const decision = getDecision();
    switch (decision) {
      case 'Approved':
        return <CheckCircle className="h-6 w-6 text-green-500" />;
      case 'Rejected':
        return <XCircle className="h-6 w-6 text-red-500" />;
      case 'Escalated':
        return <AlertTriangle className="h-6 w-6 text-amber-500" />;
      case 'Flagged':
        return <Flag className="h-6 w-6 text-purple-500" />;
      default:
        return null;
    }
  };

  return (
    <div className="container mx-auto max-w-4xl space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          onClick={() => navigate('/submitter/submissions')}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to My Submissions
        </Button>
        {/* Genre may not be present in tally; optional */}
        {/* <Badge variant="secondary">{tally.genre}</Badge> */}
      </div>

      {/* Results Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Submission Results #{tally.submission_id ?? id}
            {getDecisionIcon()}
          </CardTitle>
          <CardDescription>
            {tally.computed_at ? `Tallied ${new Date(tally.computed_at).toLocaleDateString()}` : 'Awaiting tally'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Decision */}
          <div className="rounded-lg border bg-muted/30 p-4">
            <h3 className="mb-2 text-lg font-semibold">Decision: {(tally.decision || getDecision())}</h3>
            <p className="text-sm text-muted-foreground">
              Based on {totalVotes} anonymous votes
            </p>
          </div>

          {/* Vote Counts */}
          <div className="space-y-4">
            <h3 className="font-medium">Vote Distribution</h3>
            
            <div className="space-y-3">
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="flex items-center">
                    <CheckCircle className="mr-2 h-4 w-4 text-green-500" />
                    Approve
                  </span>
                  <span>{counts.approve} votes</span>
                </div>
                <Progress value={approvePercent} className="h-2 bg-gray-200" indicatorClassName="bg-green-500" />
              </div>
              
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="flex items-center">
                    <XCircle className="mr-2 h-4 w-4 text-red-500" />
                    Reject
                  </span>
                  <span>{counts.reject} votes</span>
                </div>
                <Progress value={rejectPercent} className="h-2 bg-gray-200" indicatorClassName="bg-red-500" />
              </div>
              
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="flex items-center">
                    <AlertTriangle className="mr-2 h-4 w-4 text-amber-500" />
                    Escalate
                  </span>
                  <span>{counts.escalate} votes</span>
                </div>
                <Progress value={escalatePercent} className="h-2 bg-gray-200" indicatorClassName="bg-amber-500" />
              </div>
              
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="flex items-center">
                    <Flag className="mr-2 h-4 w-4 text-purple-500" />
                    Flag
                  </span>
                  <span>{counts.flag} votes</span>
                </div>
                <Progress value={flagPercent} className="h-2 bg-gray-200" indicatorClassName="bg-purple-500" />
              </div>
            </div>
          </div>

          {/* Content Reference */}
          {/* Not available from tally endpoint directly; omit unless merged with submission details */}
        </CardContent>
      </Card>
    </div>
  );
}