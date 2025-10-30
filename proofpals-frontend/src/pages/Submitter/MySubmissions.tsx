import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { SubmissionList } from '@/components/submission/SubmissionList';
import { Plus } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';

export function MySubmissions() {
  const navigate = useNavigate();
  
  const { data: submissions, isLoading } = useQuery<any>({
    queryKey: ['my-submissions'],
    queryFn: () => apiClient.get('/api/v1/submissions/my'),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  if (isLoading) return <Loading />;

  return (
    <div className="flex min-h-screen">
      <Navigation role="submitter" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <div className="mb-6 flex items-center justify-between">
            <h1 className="text-3xl font-bold">My Submissions</h1>
            <Button onClick={() => navigate('/submitter/upload')}>
              <Plus className="mr-2 h-4 w-4" />
              New Submission
            </Button>
          </div>
          
          <SubmissionList submissions={submissions || []} />
        </main>
      </div>
    </div>
  );
}

