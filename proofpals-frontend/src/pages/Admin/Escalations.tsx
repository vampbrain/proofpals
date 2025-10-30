import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { ContentViewer } from '@/components/submission/ContentViewer';
import { AlertTriangle, CheckCircle, XCircle, Eye, Calendar } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { toast } from 'sonner';

export function Escalations() {
  const queryClient = useQueryClient();
  const [expandedCard, setExpandedCard] = useState<number | null>(null);
  const [resolvingId, setResolvingId] = useState<number | null>(null);

  const { data: escalationsData, isLoading } = useQuery<any>({
    queryKey: ['escalations'],
    queryFn: () => apiClient.get('/api/v1/admin/escalations'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const resolveMutation = useMutation({
    mutationFn: ({ submissionId, resolution }: { submissionId: number; resolution: string }) =>
      apiClient.post(`/api/v1/admin/escalations/${submissionId}/resolve`, { resolution }),
    onSuccess: (_, { submissionId, resolution }) => {
      toast.success(`Escalation resolved as ${resolution}d`);
      setResolvingId(null);
      setExpandedCard(null);
      queryClient.invalidateQueries({ queryKey: ['escalations'] });
      queryClient.invalidateQueries({ queryKey: ['admin-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['approved-submissions'] });
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to resolve escalation');
      setResolvingId(null);
    },
  });

  const handleResolve = (submissionId: number, resolution: 'approve' | 'reject') => {
    if (confirm(`Are you sure you want to ${resolution} this escalated submission?`)) {
      setResolvingId(submissionId);
      resolveMutation.mutate({ submissionId, resolution });
    }
  };

  if (isLoading) return <Loading />;

  const escalations = escalationsData?.escalations || [];

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-8">
          <div className="mb-8">
            <h1 className="text-4xl font-light text-gray-900 mb-2">Escalations</h1>
            <p className="text-gray-500">Review and resolve escalated submissions</p>
          </div>
          
          {escalations.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <AlertTriangle className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                <h3 className="mb-2 text-lg font-semibold">No Escalations</h3>
                <p className="text-muted-foreground">
                  All submissions are currently being handled by reviewers.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {escalations.map((escalation: any) => (
                <Card key={escalation.id} className="border-orange-200">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-5 w-5 text-orange-500" />
                        <CardTitle>Submission #{escalation.id}</CardTitle>
                        <Badge variant="outline" className="capitalize text-orange-600">
                          {escalation.genre}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Calendar className="h-4 w-4" />
                        Escalated: {new Date(escalation.escalated_at).toLocaleDateString()}
                      </div>
                    </div>
                    <CardDescription>
                      This submission was escalated by a reviewer and requires admin decision.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <p className="text-sm font-medium mb-2">Content Reference:</p>
                        <p className="text-sm text-muted-foreground bg-muted p-2 rounded">
                          {escalation.content_ref}
                        </p>
                      </div>

                      {expandedCard === escalation.id ? (
                        <div className="space-y-4">
                          <div className="rounded-lg border bg-muted/50 p-4">
                            <p className="text-sm font-medium mb-2">Content Preview:</p>
                            <ContentViewer contentRef={escalation.content_ref} />
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setExpandedCard(null)}
                          >
                            <Eye className="mr-2 h-4 w-4" />
                            Hide Content
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setExpandedCard(escalation.id)}
                        >
                          <Eye className="mr-2 h-4 w-4" />
                          View Content
                        </Button>
                      )}

                      <div className="flex gap-3 pt-4 border-t">
                        <Button
                          onClick={() => handleResolve(escalation.id, 'approve')}
                          disabled={resolvingId === escalation.id}
                          className="bg-green-600 hover:bg-green-700"
                        >
                          <CheckCircle className="mr-2 h-4 w-4" />
                          {resolvingId === escalation.id ? 'Approving...' : 'Approve'}
                        </Button>
                        <Button
                          variant="destructive"
                          onClick={() => handleResolve(escalation.id, 'reject')}
                          disabled={resolvingId === escalation.id}
                        >
                          <XCircle className="mr-2 h-4 w-4" />
                          {resolvingId === escalation.id ? 'Rejecting...' : 'Reject'}
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

