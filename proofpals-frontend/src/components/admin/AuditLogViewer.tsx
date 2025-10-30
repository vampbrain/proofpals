import { Card, CardContent } from '@/components/ui/card';

interface AuditLog {
  id: number;
  action: string;
  user_id: number;
  timestamp: string;
  details: string;
}

interface AuditLogViewerProps {
  logs: AuditLog[];
}

export function AuditLogViewer({ logs }: AuditLogViewerProps) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="divide-y">
          {logs.map((log) => (
            <div key={log.id} className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">{log.action}</p>
                  <p className="text-sm text-muted-foreground">{log.details}</p>
                </div>
                <p className="text-sm text-muted-foreground">
                  {new Date(log.timestamp).toLocaleString()}
                </p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

