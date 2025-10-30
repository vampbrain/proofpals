import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { History, Vote, FileText, AlertTriangle, Flag } from 'lucide-react';
import { apiClient } from '@/lib/api/client';

export function AuditLogs() {
  const { data: logsData, isLoading } = useQuery<any>({
    queryKey: ['audit-logs'],
    queryFn: () => apiClient.get('/api/v1/admin/audit-logs'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  if (isLoading) return <Loading />;

  const logs = logsData?.logs || [];

  const getVoteIcon = (voteType: string) => {
    switch (voteType) {
      case 'approve': return <Vote className="h-4 w-4 text-green-500" />;
      case 'reject': return <Vote className="h-4 w-4 text-red-500" />;
      case 'escalate': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'flag': return <Flag className="h-4 w-4 text-red-600" />;
      default: return <FileText className="h-4 w-4 text-gray-500" />;
    }
  };

  const getVoteBadge = (voteType: string) => {
    const variants: Record<string, any> = {
      approve: 'default',
      reject: 'destructive',
      escalate: 'outline',
      flag: 'destructive'
    };
    return (
      <Badge variant={variants[voteType] || 'secondary'} className="capitalize">
        {voteType}
      </Badge>
    );
  };

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <div className="mb-8">
            <div className="flex items-center justify-between mb-2">
              <h1 className="text-4xl font-light text-gray-900">Audit Logs</h1>
              <div className="flex items-center gap-2 px-3 py-1 bg-purple-50 text-purple-700 rounded-full text-sm font-medium">
                <History className="h-4 w-4" />
                {logs.length} Records
              </div>
            </div>
            <p className="text-gray-500">Track all system activities and user interactions</p>
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>System Activity Log</CardTitle>
              <CardDescription>
                Track all voting activities and system changes (auto-refreshes every 30 seconds)
              </CardDescription>
            </CardHeader>
            <CardContent>
              {logs.length === 0 ? (
                <div className="py-8 text-center text-muted-foreground">
                  <History className="mx-auto mb-4 h-12 w-12" />
                  <h3 className="mb-2 text-lg font-semibold">No Activity Yet</h3>
                  <p>System activity will appear here as users interact with the platform.</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Submission</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Key Image</TableHead>
                      <TableHead>Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {logs.map((log: any) => (
                      <TableRow key={log.id}>
                        <TableCell className="font-mono text-sm">
                          {new Date(log.timestamp).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getVoteIcon(log.action.split(': ')[1])}
                            {getVoteBadge(log.action.split(': ')[1])}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <FileText className="h-4 w-4 text-muted-foreground" />
                            #{log.submission_id}
                            <Badge variant="outline" className="text-xs">
                              {log.submission_genre}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="capitalize">
                            {log.submission_status}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {log.key_image}
                        </TableCell>
                        <TableCell className="max-w-md truncate text-sm text-muted-foreground">
                          {log.details}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}

