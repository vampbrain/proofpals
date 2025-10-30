import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { Shield, KeyRound, CheckCircle, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

function randomHex64(): string {
  const chars = 'abcdef0123456789';
  let out = '';
  for (let i = 0; i < 64; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

export function CredentialAllocation() {
  const [credentialHash, setCredentialHash] = useState('');
  const [profileHash, setProfileHash] = useState('');

  const { mutateAsync, isPending } = useMutation({
    mutationFn: async (payload: { credential_hash: string; profile_hash?: string | null }) => {
      const res = await apiClient.post(API_ENDPOINTS.vetterRegisterCredential, payload);
      return (res as { data: any }).data;
    },
  });

  const handleGenerate = () => {
    const v = randomHex64();
    setCredentialHash(v);
    toast.info('Generated 64-char credential hash');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = credentialHash.trim();
    if (trimmed.length !== 64) {
      toast.error('Credential hash must be exactly 64 characters');
      return;
    }
    try {
      const payload = { credential_hash: trimmed, profile_hash: profileHash?.trim() || null };
      const data = await mutateAsync(payload);
      toast.success('Credential registered');
      setCredentialHash('');
      setProfileHash('');
    } catch (err: any) {
      const message = err?.response?.data?.detail || err?.message || 'Registration failed';
      toast.error(message);
    }
  };

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <h1 className="mb-6 text-3xl font-bold">Credential Allocation</h1>

          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-2">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
                  <KeyRound className="h-6 w-6 text-blue-600" />
                </div>
                <CardTitle className="text-xl text-center">Allocate Reviewer Credential</CardTitle>
                <CardDescription className="text-center">
                  Admins and vetters can register credential hashes for reviewers
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertDescription>
                      This registers a reviewer credential. Reviewers can later present it to mint tokens.
                    </AlertDescription>
                  </Alert>

                  <div className="space-y-2">
                    <Label htmlFor="credentialHash">Credential Hash (64 hex chars)</Label>
                    <Input
                      id="credentialHash"
                      placeholder="e.g. a1b2c3... (64 chars)"
                      value={credentialHash}
                      onChange={(e) => setCredentialHash(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Button type="button" variant="secondary" onClick={handleGenerate}>
                        Generate Random
                      </Button>
                      <Button type="submit" disabled={isPending}>
                        {isPending ? 'Registering...' : 'Register Credential'}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="profileHash">Profile Hash (optional)</Label>
                    <Input
                      id="profileHash"
                      placeholder="Optional opaque identifier"
                      value={profileHash}
                      onChange={(e) => setProfileHash(e.target.value)}
                    />
                  </div>

                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      Ensure you follow issuance policy. Do not link real identities.
                    </AlertDescription>
                  </Alert>
                </form>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}