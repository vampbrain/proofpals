import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface EscalationCardProps {
  escalation: {
    id: number;
    submission_id: number;
    reason: string;
    status: string;
    created_at: string;
  };
}

export function EscalationCard({ escalation }: EscalationCardProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Escalation #{escalation.id}</CardTitle>
          <Badge variant="destructive">{escalation.status}</Badge>
        </div>
        <CardDescription>
          Submission #{escalation.submission_id} • {new Date(escalation.created_at).toLocaleDateString()}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{escalation.reason}</p>
      </CardContent>
    </Card>
  );
}

