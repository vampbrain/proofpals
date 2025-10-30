import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { SystemStatus } from '@/components/system/SystemStatus';
import { IntegrationTest } from '@/components/system/IntegrationTest';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { BarChart3, Users, FileText, AlertTriangle, CheckCircle, XCircle, Clock, Flag } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { toast } from 'sonner';

export function AdminDashboard() {
  const queryClient = useQueryClient();
  
  const { data: stats, isLoading: statsLoading } = useQuery<any>({
    queryKey: ['admin-stats'],
    queryFn: () => apiClient.get('/api/v1/monitoring/statistics'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: submissions, isLoading: submissionsLoading } = useQuery<any>({
    queryKey: ['admin-submissions'],
    queryFn: () => apiClient.get('/api/v1/submissions'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: flaggedSubmissions, isLoading: flaggedLoading } = useQuery<any>({
    queryKey: ['admin-flagged'],
    queryFn: () => apiClient.get('/api/v1/admin/flagged'),
    refetchOnWindowFocus: false, // Don't refetch when window gains focus
  });

  const { data: systemStatus } = useQuery<any>({
    queryKey: ['system-status'],
    queryFn: () => apiClient.get('/api/v1/system/status'),
    refetchInterval: 15000, // Refresh every 15 seconds
  });

  const reviewMutation = useMutation({
    mutationFn: async ({ submissionId, action }: { submissionId: number; action: string }) => {
      return apiClient.post(`/api/v1/admin/submissions/${submissionId}/review`, { action });
    },
    onSuccess: (data, variables) => {
      toast.success(`Submission ${variables.action}ed successfully!`);
      queryClient.invalidateQueries({ queryKey: ['admin-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['admin-flagged'] });
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || `Failed to review submission`);
    },
  });

  const handleReviewSubmission = (submissionId: number, action: string) => {
    reviewMutation.mutate({ submissionId, action });
  };

  if (statsLoading || submissionsLoading || flaggedLoading) return <Loading />;

  // Group submissions by status
  const submissionsByStatus = submissions?.reduce((acc: any, sub: any) => {
    acc[sub.status] = (acc[sub.status] || 0) + 1;
    return acc;
  }, {}) || {};

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'rejected': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'pending': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'escalated': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'flagged': return <Flag className="h-4 w-4 text-red-600" />;
      default: return <FileText className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, any> = {
      approved: 'default',
      rejected: 'destructive', 
      pending: 'secondary',
      escalated: 'outline',
      flagged: 'destructive'
    };
    return (
      <Badge variant={variants[status] || 'secondary'} className="capitalize">
        {status}
      </Badge>
    );
  };

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-8 space-y-8">
          {/* Header */}
          <div className="border-b border-gray-200 pb-6">
            <h1 className="text-4xl font-light text-gray-900 mb-2">Admin Dashboard</h1>
            <p className="text-gray-500">Real-time platform insights and analytics</p>
          </div>

          {/* System Overview Cards - First */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
            <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
              <h2 className="text-lg font-semibold text-gray-900">System Overview</h2>
            </div>
            <div className="p-6">
              <div className="grid gap-4 md:grid-cols-5">
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-yellow-800">Pending</span>
                    <Clock className="h-4 w-4 text-yellow-600" />
                  </div>
                  <div className="text-2xl font-bold text-yellow-700">{submissionsByStatus.pending || 0}</div>
                  <p className="text-xs text-yellow-600 mt-1">Awaiting review</p>
                </div>

                <div className="bg-green-50 border border-green-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-green-800">Approved</span>
                    <CheckCircle className="h-4 w-4 text-green-600" />
                  </div>
                  <div className="text-2xl font-bold text-green-700">{submissionsByStatus.approved || 0}</div>
                  <p className="text-xs text-green-600 mt-1">Successfully reviewed</p>
                </div>

                <div className="bg-red-50 border border-red-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-red-800">Rejected</span>
                    <XCircle className="h-4 w-4 text-red-600" />
                  </div>
                  <div className="text-2xl font-bold text-red-700">{submissionsByStatus.rejected || 0}</div>
                  <p className="text-xs text-red-600 mt-1">Did not meet standards</p>
                </div>

                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-orange-800">Escalated</span>
                    <AlertTriangle className="h-4 w-4 text-orange-600" />
                  </div>
                  <div className="text-2xl font-bold text-orange-700">{submissionsByStatus.escalated || 0}</div>
                  <p className="text-xs text-orange-600 mt-1">Needs admin review</p>
                </div>

                <div className="bg-red-50 border border-red-300 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-red-900">Flagged</span>
                    <Flag className="h-4 w-4 text-red-700" />
                  </div>
                  <div className="text-2xl font-bold text-red-800">{submissionsByStatus.flagged || 0}</div>
                  <p className="text-xs text-red-700 mt-1">Potentially harmful</p>
                </div>
              </div>
            </div>
          </div>

          {/* System Metrics - Second */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
            <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
              <h2 className="text-lg font-semibold text-gray-900">System Metrics</h2>
            </div>
            <div className="p-6">
              <div className="grid gap-4 md:grid-cols-4">
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-blue-800">Total Submissions</span>
                    <FileText className="h-4 w-4 text-blue-600" />
                  </div>
                  <div className="text-2xl font-bold text-blue-700">4</div>
                  <p className="text-xs text-blue-600 mt-1">All time submissions</p>
                </div>

                <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-purple-800">Active Rings</span>
                    <Users className="h-4 w-4 text-purple-600" />
                  </div>
                  <div className="text-2xl font-bold text-purple-700">1</div>
                  <p className="text-xs text-purple-600 mt-1">Ring signatures available</p>
                </div>

                <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-emerald-800">Available Tokens</span>
                    <BarChart3 className="h-4 w-4 text-emerald-600" />
                  </div>
                  <div className="text-2xl font-bold text-emerald-700">19</div>
                  <p className="text-xs text-emerald-600 mt-1">For anonymous voting</p>
                </div>

                <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-indigo-800">Total Reviewers</span>
                    <Users className="h-4 w-4 text-indigo-600" />
                  </div>
                  <div className="text-2xl font-bold text-indigo-700">3</div>
                  <p className="text-xs text-indigo-600 mt-1">Active peer reviewers</p>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Submissions */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Recent Submissions</h3>
            <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
              <Table>
                <TableHeader className="bg-gray-50/50">
                  <TableRow className="border-b border-gray-200">
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">ID</TableHead>
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">Genre</TableHead>
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">Content</TableHead>
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">Status</TableHead>
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">Submitted</TableHead>
                    <TableHead className="font-semibold text-gray-900 px-6 py-4">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {submissions && submissions.length > 0 ? (
                    submissions.slice(0, 5).map((submission: any) => (
                      <TableRow key={submission.id} className="border-b border-gray-100 hover:bg-gray-50/50 transition-colors">
                        <TableCell className="font-medium text-blue-600 px-6 py-4">#{submission.id}</TableCell>
                        <TableCell className="text-gray-900 px-6 py-4 capitalize">{submission.genre}</TableCell>
                        <TableCell className="max-w-xs truncate text-gray-600 px-6 py-4">
                          {submission.content_ref}
                        </TableCell>
                        <TableCell className="px-6 py-4">
                          <Badge className={`px-2 py-1 rounded-md font-medium ${
                            submission.status === 'approved' ? 'bg-green-50 text-green-700 border border-green-200' :
                            submission.status === 'rejected' ? 'bg-red-50 text-red-700 border border-red-200' :
                            submission.status === 'pending' ? 'bg-yellow-50 text-yellow-700 border border-yellow-200' :
                            submission.status === 'escalated' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
                            submission.status === 'flagged' ? 'bg-red-50 text-red-700 border border-red-200' :
                            'bg-gray-50 text-gray-700 border border-gray-200'
                          }`}>
                            {getStatusIcon(submission.status)}
                            {submission.status.charAt(0).toUpperCase() + submission.status.slice(1)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-600 px-6 py-4">
                          {new Date(submission.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="px-6 py-4">
                          {submission.status === 'pending' && (
                            <div className="flex gap-2">
                              <Button 
                                size="sm" 
                                variant="outline"
                                className="text-green-600 border-green-200 hover:bg-green-50"
                                onClick={() => handleReviewSubmission(submission.id, 'approve')}
                              >
                                Approve
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                className="text-red-600 border-red-200 hover:bg-red-50"
                                onClick={() => handleReviewSubmission(submission.id, 'reject')}
                              >
                                Reject
                              </Button>
                            </div>
                          )}
                          {submission.status === 'flagged' && (
                            <div className="space-y-2">
                              <div className="flex gap-2">
                                <Button 
                                  size="sm" 
                                  variant="outline"
                                  className="text-green-600 border-green-200 hover:bg-green-50"
                                  onClick={() => handleReviewSubmission(submission.id, 'approve')}
                                >
                                  Approve
                                </Button>
                                <Button 
                                  size="sm" 
                                  variant="outline"
                                  className="text-red-600 border-red-200 hover:bg-red-50"
                                  onClick={() => handleReviewSubmission(submission.id, 'reject')}
                                >
                                  Reject
                                </Button>
                              </div>
                              <div className="text-xs text-red-700 bg-red-50 p-2 rounded border">
                                <div className="font-semibold mb-1">🚨 Submitter Info:</div>
                                <div className="font-mono text-xs">
                                  {(() => {
                                    if (flaggedLoading) {
                                      return <div>Loading submitter info...</div>;
                                    }
                                    
                                    const flaggedSub = flaggedSubmissions?.flagged_submissions?.find((fs: any) => fs.id === submission.id);
                                    
                                    if (!flaggedSub) {
                                      return <div>Submitter info not available</div>;
                                    }
                                    
                                    return (
                                      <>
                                        <div>IP: {flaggedSub.submitter_ip_hash?.substring(0, 20) || 'No IP data'}...</div>
                                        <div>MAC: {flaggedSub.submitter_mac_hash?.substring(0, 20) || 'No MAC data'}...</div>
                                      </>
                                    );
                                  })()}
                                </div>
                              </div>
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-gray-500">
                        No submissions found
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </div>

          {/* Flagged Submissions - URGENT */}
          {flaggedSubmissions && flaggedSubmissions.flagged_submissions && flaggedSubmissions.flagged_submissions.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <Flag className="h-5 w-5 text-red-600" />
                <h3 className="text-lg font-semibold text-red-900">🚨 Flagged Content - Submitter Information</h3>
                <Badge variant="destructive" className="ml-2">URGENT</Badge>
              </div>
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <p className="text-sm text-red-800 mb-4">
                  ⚠️ The following content has been flagged by reviewers. Submitter IP/MAC hashes are provided for investigation.
                </p>
                <div className="overflow-hidden rounded-lg border border-red-300 bg-white shadow-sm">
                  <Table>
                    <TableHeader className="bg-red-100">
                      <TableRow className="border-b border-red-200">
                        <TableHead className="font-semibold text-red-900 px-6 py-4">ID</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">Genre</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">Content</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">IP Hash</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">MAC Hash</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">Flagged</TableHead>
                        <TableHead className="font-semibold text-red-900 px-6 py-4">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {flaggedSubmissions.flagged_submissions.map((submission: any) => (
                        <TableRow key={submission.id} className="border-b border-red-100 hover:bg-red-50/50 transition-colors">
                          <TableCell className="font-medium text-red-600 px-6 py-4">#{submission.id}</TableCell>
                          <TableCell className="text-gray-900 px-6 py-4 capitalize">{submission.genre}</TableCell>
                          <TableCell className="max-w-xs truncate text-gray-600 px-6 py-4">
                            {submission.content_ref}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-gray-800 px-6 py-4 max-w-32 truncate">
                            {submission.submitter_ip_hash || 'N/A'}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-gray-800 px-6 py-4 max-w-32 truncate">
                            {submission.submitter_mac_hash || 'N/A'}
                          </TableCell>
                          <TableCell className="text-gray-600 px-6 py-4">
                            {new Date(submission.created_at).toLocaleDateString()}
                          </TableCell>
                          <TableCell className="px-6 py-4">
                            <div className="flex gap-2">
                              <Button 
                                size="sm" 
                                variant="outline"
                                className="text-green-600 border-green-200 hover:bg-green-50"
                                onClick={() => handleReviewSubmission(submission.id, 'approve')}
                              >
                                Approve
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                className="text-red-600 border-red-200 hover:bg-red-50"
                                onClick={() => handleReviewSubmission(submission.id, 'reject')}
                              >
                                Reject
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </div>
          )}

          {/* System Integration Status */}
          <SystemStatus />

          {/* Integration Test */}
          <IntegrationTest />
        </main>
      </div>
    </div>
  );
}

