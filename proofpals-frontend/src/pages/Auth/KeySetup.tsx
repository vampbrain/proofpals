import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Key, AlertCircle, CheckCircle } from 'lucide-react';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { toast } from 'sonner';

export function KeySetup() {
  const navigate = useNavigate();
  const { generateKeyPair, hasKeyPair } = useCryptoStore();
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      await generateKeyPair();
      toast.success('Key pair generated successfully!');
      navigate('/');
    } catch (error: any) {
      toast.error(error.message || 'Failed to generate key pair');
    } finally {
      setIsGenerating(false);
    }
  };

  if (hasKeyPair()) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <CardTitle className="text-center">Keys Already Set Up</CardTitle>
            <CardDescription className="text-center">
              Your cryptographic keys are already configured
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" onClick={() => navigate('/')}>
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-2 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
            <Key className="h-6 w-6 text-blue-600" />
          </div>
          <CardTitle>Set Up Cryptographic Keys</CardTitle>
          <CardDescription>
            Generate your identity key pair for anonymous voting
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <Shield className="h-4 w-4" />
            <AlertDescription>
              Your keys are stored locally in your browser. They are never sent to our servers.
            </AlertDescription>
          </Alert>

          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              <strong>Important:</strong> Make sure to backup your keys. If you lose them, you 
              cannot recover your voting identity.
            </AlertDescription>
          </Alert>

          <Button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="w-full"
            size="lg"
          >
            {isGenerating ? 'Generating keys...' : 'Generate Keys'}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

