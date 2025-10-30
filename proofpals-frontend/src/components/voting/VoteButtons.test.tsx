// src/components/voting/VoteButtons.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { VoteButtons } from './VoteButtons';

describe('VoteButtons', () => {
  it('renders all vote options', () => {
    const onVote = vi.fn();
    render(<VoteButtons submissionId={1} onVote={onVote} />);
    
    expect(screen.getByText('Approve')).toBeInTheDocument();
    expect(screen.getByText('Escalate')).toBeInTheDocument();
    expect(screen.getByText('Reject')).toBeInTheDocument();
    expect(screen.getByText('Flag')).toBeInTheDocument();
  });

  it('shows confirmation modal on vote click', () => {
    const onVote = vi.fn();
    render(<VoteButtons submissionId={1} onVote={onVote} />);
    
    fireEvent.click(screen.getByText('Approve'));
    
    expect(screen.getByText('Confirm Anonymous Vote')).toBeInTheDocument();
  });

  it('does not log sensitive data', () => {
    const consoleSpy = vi.spyOn(console, 'log');
    const onVote = vi.fn();
    
    render(<VoteButtons submissionId={1} onVote={onVote} />);
    
    // Ensure no sensitive data in logs
    expect(consoleSpy).not.toHaveBeenCalledWith(
      expect.stringContaining('secretKey')
    );
  });
});