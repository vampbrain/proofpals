// tests/e2e/voting.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Anonymous Voting Flow', () => {
  test('reviewer can submit anonymous vote', async ({ page }) => {
    // Setup: Login as reviewer
    await page.goto('/login');
    // ... login flow
    
    // Navigate to review page
    await page.goto('/review');
    
    // Should show submission
    await expect(page.locator('[data-testid="submission-content"]')).toBeVisible();
    
    // Click Approve button
    await page.click('button:has-text("Approve")');
    
    // Confirmation modal should appear
    await expect(page.locator('text=Confirm Anonymous Vote')).toBeVisible();
    // Verify privacy notice is shown
    await expect(page.locator('text=Your identity will remain anonymous')).toBeVisible();
    
    // Confirm vote
    await page.click('button:has-text("Confirm & Submit")');
    
    // Should show success message
    await expect(page.locator('text=Vote submitted successfully')).toBeVisible();
    
    // Verify no sensitive data in console
    const consoleLogs: string[] = [];
    page.on('console', msg => consoleLogs.push(msg.text()));
    expect(consoleLogs.join('')).not.toContain('secretKey');
    expect(consoleLogs.join('')).not.toContain('seed');

  });

  test('prevents double voting', async ({ page }) => {
    await page.goto('/review');
    
    // Submit first vote
    await page.click('button:has-text("Approve")');
    await page.click('button:has-text("Confirm & Submit")');
    await expect(page.locator('text=Vote submitted successfully')).toBeVisible();
    
    // Try to vote again on same submission
    await page.click('button:has-text("Reject")');
    await page.click('button:has-text("Confirm & Submit")');
    
    // Should show error
    await expect(page.locator('text=already voted')).toBeVisible();
  });
});