import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Header } from '@/components/common/Header';
import { Loading } from '@/components/common/Loading';
import { ArrowLeft } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { StatusBadge } from '@/components/submission/StatusBadge';

export function SubmissionDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: submission, isLoading } = useQuery<any>({
    queryKey: ['submission', id],
    queryFn: () => apiClient.get(API_ENDPOINTS.submission(Number(id))),
    enabled: !!id,
  });

  if (isLoading) return <Loading />;

  if (!submission) {
    return (
      <div className="flex min-h-screen">
        <Header />
        <main className="container mx-auto p-6">
          <p>Submission not found</p>
        </main>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Header />
      <main className="container mx-auto max-w-4xl p-6">
        <Button
          variant="ghost"
          className="mb-6"
          onClick={() => navigate('/submitter/submissions')}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Submissions
        </Button>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Submission #{submission.submission_id}</CardTitle>
              <StatusBadge status={submission.status} />
            </div>
            <CardDescription>
              Submitted {new Date(submission.created_at).toLocaleDateString()}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h3 className="font-semibold">Genre</h3>
              <Badge>{submission.genre}</Badge>
            </div>
            <div>
              <h3 className="font-semibold">Content Reference</h3>
              <p className="text-sm text-muted-foreground">{submission.content_ref}</p>
            </div>
            {submission.review_count > 0 && (
              <div>
                <h3 className="font-semibold">Review Status</h3>
                <p className="text-sm">
                  {submission.review_count} reviewer(s) have evaluated this submission
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

