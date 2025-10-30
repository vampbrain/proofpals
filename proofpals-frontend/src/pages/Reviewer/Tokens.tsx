// src/pages/Reviewer/Tokens.tsx
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, KeyRound, Copy } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { useAuthStore } from '@/store/authStore';

const tokenRequestSchema = z.object({
  credential_hash: z.string().min(1, 'Credential hash is required'),
  epoch: z.number().int().positive('Epoch must be a positive integer'),
  token_count: z.number().int().min(1).max(100),
});

type TokenRequestForm = z.infer<typeof tokenRequestSchema>;

export function TokensPage() {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const { addTokens, hasKeyPair, generateKeyPair, getPublicKeyHex, fetchPublicKey } = useCryptoStore();
  const [isLoading, setIsLoading] = useState(false);
  const [isFetchingKeys, setIsFetchingKeys] = useState(false);
  const pubkeyHex = getPublicKeyHex();

  // Auto-fetch public key on component mount if not available
  useEffect(() => {
    if (!pubkeyHex && !isFetchingKeys) {
      setIsFetchingKeys(true);
      fetchPublicKey()
        .then(() => {
          console.log('✅ Auto-fetched public key from server');
        })
        .catch((error) => {
          console.warn('⚠️ Could not auto-fetch public key:', error);
        })
        .finally(() => {
          setIsFetchingKeys(false);
        });
    }
  }, [pubkeyHex, fetchPublicKey, isFetchingKeys]);

  const { register, handleSubmit, formState: { errors } } = useForm<TokenRequestForm>({
    resolver: zodResolver(tokenRequestSchema),
    defaultValues: {
      credential_hash: '',
      epoch: Math.floor(Date.now() / 1000),
      token_count: 5,
    },
  });

  const presentMutation = useMutation({
    mutationFn: async (payload: TokenRequestForm) => {
      return apiClient.post<{ success: boolean; tokens?: string[] }>(API_ENDPOINTS.presentCredential, payload);
    },
    onSuccess: (data) => {
      const tokens = data?.tokens || [];
      if (tokens.length > 0) {
        addTokens(tokens);
        toast.success(`Received ${tokens.length} epoch tokens`);
        navigate('/reviewer/dashboard');
      } else {
        toast.warning('No tokens returned');
      }
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || error.response?.data?.error || 'Failed to get tokens');
    },
  });

  const publishKeyMutation = useMutation({
    mutationFn: async () => {
      if (!pubkeyHex) throw new Error('No public key');
      return apiClient.post(API_ENDPOINTS.publishPublicKey, { public_key_hex: pubkeyHex });
    },
    onSuccess: () => {
      toast.success('Public key published to server');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to publish public key');
    },
  });

  const onSubmit = (data: TokenRequestForm) => {
    setIsLoading(true);
    presentMutation.mutate(data, {
      onSettled: () => setIsLoading(false),
    });
  };

  return (
    <div className="flex min-h-screen">
      <Navigation role={user?.role as 'admin' | 'reviewer' | 'submitter'} />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto max-w-3xl space-y-8 p-6">
      <div className="mb-8">
        <h1 className="text-4xl font-light text-gray-900 mb-2">Get Epoch Tokens</h1>
        <p className="text-gray-500">Present your credential to receive tokens for anonymous voting</p>
      </div>

      <Alert className="border-yellow-200 bg-yellow-50">
        <Shield className="h-4 w-4 text-yellow-700" />
        <AlertDescription className="text-yellow-900">
          This demo accepts a simple credential hash and epoch. In production, this flow uses blind signatures and verification.
        </AlertDescription>
      </Alert>

      <form onSubmit={handleSubmit(onSubmit)}>
        <Card>
          <CardHeader>
            <CardTitle>Credential Presentation</CardTitle>
            <CardDescription>Provide your credential details to mint tokens</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="rounded border p-3 bg-muted/30 text-sm">
              <div className="mb-2 font-medium">Your Public Key (hex)</div>
              <div className="break-all text-xs">{pubkeyHex || 'No keypair yet. Generate keys first.'}</div>
              <div className="mt-2 flex gap-2">
                <Button type="button" size="sm" variant="outline" onClick={() => {
                  if (pubkeyHex) {
                    navigator.clipboard.writeText(pubkeyHex);
                    toast.success('Public key copied');
                  }
                }}>
                  <Copy className="mr-2 h-3 w-3" /> Copy
                </Button>
                <Button type="button" size="sm" onClick={() => publishKeyMutation.mutate()} disabled={!pubkeyHex || publishKeyMutation.isPending}>
                  {publishKeyMutation.isPending ? 'Publishing...' : 'Publish to Server'}
                </Button>
              </div>
              {!hasKeyPair() && (
                <div className="mt-2 flex gap-2">
                  <Button type="button" variant="outline" onClick={async () => {
                    setIsFetchingKeys(true);
                    try {
                      await fetchPublicKey();
                      toast.success('Keys fetched from server!');
                    } catch (error) {
                      console.error('Failed to fetch keys:', error);
                      toast.error('Failed to fetch keys from server');
                    } finally {
                      setIsFetchingKeys(false);
                    }
                  }} disabled={isFetchingKeys}>
                    {isFetchingKeys ? 'Fetching...' : 'Fetch Keys from Server'}
                  </Button>
                  <Button type="button" variant="outline" onClick={async () => {
                    await generateKeyPair();
                  }}>
                    Generate Local Keys
                  </Button>
                </div>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="credential_hash">Credential Hash *</Label>
              <Input id="credential_hash" placeholder="e.g. 0xabc..." {...register('credential_hash')} />
              {errors.credential_hash && (
                <p className="text-sm text-red-600">{errors.credential_hash.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="epoch">Epoch *</Label>
              <Input id="epoch" type="number" {...register('epoch', { valueAsNumber: true })} />
              {errors.epoch && (
                <p className="text-sm text-red-600">{errors.epoch.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="token_count">Token Count *</Label>
              <Input id="token_count" type="number" {...register('token_count', { valueAsNumber: true })} />
              {errors.token_count && (
                <p className="text-sm text-red-600">{errors.token_count.message}</p>
              )}
            </div>

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? (
                <>
                  <KeyRound className="mr-2 h-4 w-4 animate-pulse" />
                  Minting Tokens...
                </>
              ) : (
                <>
                  <KeyRound className="mr-2 h-4 w-4" />
                  Get Tokens
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </form>
        </main>
      </div>
    </div>
  );
}