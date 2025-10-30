import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { BarChart3, Users, FileText, Vote, CheckCircle, XCircle, AlertTriangle, Flag, Clock, KeyRound } from 'lucide-react';
import { apiClient } from '@/lib/api/client';

export function Statistics() {
  const { data: stats, isLoading } = useQuery<any>({
    queryKey: ['statistics'],
    queryFn: () => apiClient.get('/api/v1/admin/statistics'),
    refetchInterval: 60000, // Refresh every minute
  });

  if (isLoading) return <Loading />;

  const data = stats || {};
  const submissions = data.submissions || {};
  const votes = data.votes || {};
  const rings = data.rings || {};
  const tokens = data.tokens || {};
  const reviewers = data.reviewers || {};

  const totalSubmissions = submissions.total || 0;
  const approvalRate = totalSubmissions > 0 ? Math.round((submissions.approved / totalSubmissions) * 100) : 0;
  const rejectionRate = totalSubmissions > 0 ? Math.round((submissions.rejected / totalSubmissions) * 100) : 0;
  const tokenUsageRate = tokens.total > 0 ? Math.round((tokens.used / tokens.total) * 100) : 0;

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <div className="mb-8">
            <div className="flex items-center justify-between mb-2">
              <h1 className="text-4xl font-light text-gray-900">Statistics</h1>
              <div className="flex items-center gap-2 px-3 py-1 bg-blue-50 text-blue-700 rounded-full text-sm font-medium">
                <BarChart3 className="h-4 w-4" />
                Live Data
              </div>
            </div>
            <p className="text-gray-500">Comprehensive platform analytics and insights</p>
          </div>

          {/* Overview Cards */}
          <div className="grid gap-4 md:grid-cols-4 mb-6">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Total Submissions</CardTitle>
                <FileText className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{totalSubmissions}</div>
                <p className="text-xs text-muted-foreground">
                  {submissions.pending || 0} pending review
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Total Votes</CardTitle>
                <Vote className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{votes.total || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Community decisions
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Active Reviewers</CardTitle>
                <Users className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{reviewers.total || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Registered reviewers
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Token Usage</CardTitle>
                <KeyRound className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{tokenUsageRate}%</div>
                <p className="text-xs text-muted-foreground">
                  {tokens.used || 0} of {tokens.total || 0} used
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Statistics */}
          <div className="grid gap-6 md:grid-cols-2">
            {/* Submission Status Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle>Submission Status</CardTitle>
                <CardDescription>
                  Distribution of submission outcomes
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Approved</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{submissions.approved || 0}</span>
                      <Badge variant="default">{approvalRate}%</Badge>
                    </div>
                  </div>
                  <Progress value={approvalRate} className="h-2" />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-sm">Rejected</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{submissions.rejected || 0}</span>
                      <Badge variant="destructive">{rejectionRate}%</Badge>
                    </div>
                  </div>
                  <Progress value={rejectionRate} className="h-2" />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4 text-yellow-500" />
                      <span className="text-sm">Pending</span>
                    </div>
                    <span className="text-sm font-medium">{submissions.pending || 0}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500" />
                      <span className="text-sm">Escalated</span>
                    </div>
                    <span className="text-sm font-medium">{submissions.escalated || 0}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Flag className="h-4 w-4 text-red-600" />
                      <span className="text-sm">Flagged</span>
                    </div>
                    <span className="text-sm font-medium">{submissions.flagged || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Vote Type Distribution */}
            <Card>
              <CardHeader>
                <CardTitle>Vote Distribution</CardTitle>
                <CardDescription>
                  How reviewers are voting on submissions
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Approve Votes</span>
                    </div>
                    <span className="text-sm font-medium">{votes.approve || 0}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-sm">Reject Votes</span>
                    </div>
                    <span className="text-sm font-medium">{votes.reject || 0}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500" />
                      <span className="text-sm">Escalate Votes</span>
                    </div>
                    <span className="text-sm font-medium">{votes.escalate || 0}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Flag className="h-4 w-4 text-red-600" />
                      <span className="text-sm">Flag Votes</span>
                    </div>
                    <span className="text-sm font-medium">{votes.flag || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* System Resources */}
            <Card>
              <CardHeader>
                <CardTitle>System Resources</CardTitle>
                <CardDescription>
                  Ring and token availability
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Active Rings</span>
                  <Badge variant="outline">{rings.active || 0} / {rings.total || 0}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Available Tokens</span>
                  <Badge variant="outline">{tokens.available || 0}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Used Tokens</span>
                  <Badge variant="outline">{tokens.used || 0}</Badge>
                </div>
              </CardContent>
            </Card>

            {/* Genre Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle>Content by Genre</CardTitle>
                <CardDescription>
                  Submission distribution across categories
                </CardDescription>
              </CardHeader>
              <CardContent>
                {submissions.by_genre && Object.keys(submissions.by_genre).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(submissions.by_genre).map(([genre, count]: [string, any]) => (
                      <div key={genre} className="flex items-center justify-between">
                        <span className="text-sm capitalize">{genre}</span>
                        <Badge variant="secondary">{count}</Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No genre data available</p>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}

