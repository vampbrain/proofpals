import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface StatisticsPanelProps {
  data: Record<string, any>;
}

export function StatisticsPanel({ data }: StatisticsPanelProps) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Voting Statistics</CardTitle>
          <CardDescription>Overview of voting activity</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Votes:</span>
              <span className="font-semibold">{data.total_votes || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Approved:</span>
              <span className="font-semibold">{data.approved_count || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Rejected:</span>
              <span className="font-semibold">{data.rejected_count || 0}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Submission Statistics</CardTitle>
          <CardDescription>Content submission metrics</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Pending Review:</span>
              <span className="font-semibold">{data.pending_review || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Under Review:</span>
              <span className="font-semibold">{data.under_review || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Completed:</span>
              <span className="font-semibold">{data.completed || 0}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

