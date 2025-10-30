import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { SubmissionList } from '@/components/submission/SubmissionList';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export function ReviewerSubmissions() {
  const navigate = useNavigate();

  const { data: submissions, isLoading } = useQuery<any>({
    queryKey: ['all-submissions'],
    queryFn: () => apiClient.get(API_ENDPOINTS.submissions),
  });

  if (isLoading) return <Loading />;

  return (
    <div className="flex min-h-screen">
      <Navigation role="reviewer" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <div className="mb-6">
            <h1 className="text-3xl font-bold">Submissions</h1>
            <p className="text-muted-foreground">Browse and pick a submission to review</p>
          </div>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>How it works</CardTitle>
              <CardDescription>Select a submission to open the review page</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                You can review any pending submission. Your votes are anonymous and recorded cryptographically.
              </p>
            </CardContent>
          </Card>

          <SubmissionList
            submissions={submissions || []}
            onOpen={(id) => navigate(`/review/${id}`)}
          />
        </main>
      </div>
    </div>
  );
}