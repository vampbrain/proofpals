import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { StatusBadge } from './StatusBadge';

interface SubmissionListProps {
  submissions: Array<{
    submission_id: number;
    genre: string;
    content_ref: string;
    status: string;
    created_at: string;
  }>;
  onOpen?: (submissionId: number) => void;
}

export function SubmissionList({ submissions, onOpen }: SubmissionListProps) {
  const navigate = useNavigate();

  if (submissions.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">
          No submissions yet. Upload your first submission to get started!
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {submissions.map((submission) => (
        <Card
          key={submission.submission_id}
          className="cursor-pointer hover:bg-gray-50"
          onClick={() => {
            if (onOpen) {
              onOpen(submission.submission_id);
            } else {
              navigate(`/submitter/submissions/${submission.submission_id}`);
            }
          }}
        >
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Submission #{submission.submission_id}</CardTitle>
              <StatusBadge status={submission.status} />
            </div>
            <CardDescription>
              {submission.genre} • {new Date(submission.created_at).toLocaleDateString()}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{submission.content_ref}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

