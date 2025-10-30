import { Badge } from '@/components/ui/badge';

interface StatusBadgeProps {
  status: string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const variants: Record<string, 'default' | 'secondary' | 'destructive'> = {
    pending: 'secondary',
    'under_review': 'secondary',
    approved: 'default',
    rejected: 'destructive',
    escalated: 'destructive',
  };

  return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>;
}

