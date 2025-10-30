export const APP_NAME = 'ProofPals';
export const APP_VERSION = '1.0.0';

export const GENRES = [
  'news',
  'research',
  'music',
  'video',
  'literature',
  'art',
] as const;

export const VOTE_TYPES = {
  APPROVE: 'approve',
  ESCALATE: 'escalate',
  REJECT: 'reject',
  FLAG: 'flag',
} as const;

export const SUBMISSION_STATUS = {
  PENDING: 'pending',
  UNDER_REVIEW: 'under_review',
  APPROVED: 'approved',
  REJECTED: 'rejected',
  ESCALATED: 'escalated',
} as const;

export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
export const ALLOWED_FILE_TYPES = ['.pdf', '.epub', '.txt', '.docx'];

export const EPOCH_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

