// src/components/system/SystemStatus.tsx
import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  RefreshCw, 
  Database, 
  Key, 
  Shield, 
  Coins, 
  Vote,
  Settings
} from 'lucide-react';
import { backendIntegration, BackendStatus, SystemRequirements } from '@/lib/services/backendIntegration';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { toast } from 'sonner';

interface SystemStatusProps {
  className?: string;
  showActions?: boolean;
}

export function SystemStatus({ className, showActions = true }: SystemStatusProps) {
  const [status, setStatus] = useState<BackendStatus | null>(null);
  const [requirements, setRequirements] = useState<SystemRequirements | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const { tokens } = useCryptoStore();

  const checkStatus = async () => {
    setIsLoading(true);
    try {
      const [healthStatus, systemReqs] = await Promise.all([
        backendIntegration.checkSystemHealth(),
        backendIntegration.getSystemRequirements()
      ]);
      
      setStatus(healthStatus);
      setRequirements(systemReqs);
    } catch (error) {
      console.error('Failed to check system status:', error);
      toast.error('Failed to check system status');
    } finally {
      setIsLoading(false);
    }
  };

  const initializeSystem = async () => {
    setIsInitializing(true);
    try {
      console.log('🚀 Starting system initialization...');
      
      // First, ensure crypto keys are generated
      const { hasKeyPair, generateKeyPair } = useCryptoStore.getState();
      if (!hasKeyPair()) {
        console.log('🔐 Generating crypto keys...');
        await generateKeyPair();
        console.log('✅ Crypto keys generated');
      }
      
      // Then initialize the backend integration
      const result = await backendIntegration.initializeSystem();
      console.log('🌐 Backend initialization result:', result);
      
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.warning(result.message);
      }
      
      // Always refresh status after initialization
      await checkStatus();
    } catch (error: any) {
      console.error('❌ System initialization failed:', error);
      toast.error(`System initialization failed: ${error.message}`);
    } finally {
      setIsInitializing(false);
    }
  };

  const testVotingFlow = async () => {
    setIsLoading(true);
    try {
      const result = await backendIntegration.testVotingFlow();
      
      if (result.success) {
        toast.success('Voting flow test completed successfully');
        console.log('Voting flow test results:', result.details);
      } else {
        toast.error(`Voting flow test failed: ${result.details.error}`);
      }
    } catch (error) {
      toast.error('Voting flow test failed');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const initializeAndCheck = async () => {
      // Auto-initialize system on first load
      const { hasKeyPair } = useCryptoStore.getState();
      if (!hasKeyPair()) {
        console.log('🚀 Auto-initializing system on first load...');
        await initializeSystem();
      } else {
        await checkStatus();
      }
    };
    
    initializeAndCheck();
  }, []);

  const getStatusIcon = (isHealthy: boolean) => {
    return isHealthy ? (
      <CheckCircle className="h-4 w-4 text-green-600" />
    ) : (
      <XCircle className="h-4 w-4 text-red-600" />
    );
  };

  const getStatusBadge = (isHealthy: boolean, label: string) => {
    return (
      <Badge variant={isHealthy ? "default" : "destructive"} className="flex items-center gap-1">
        {getStatusIcon(isHealthy)}
        {label}
      </Badge>
    );
  };

  const overallHealth = status && 
    status.database && 
    status.crypto && 
    status.rings && 
    status.voting;

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Decentralized System Status
              </CardTitle>
              <CardDescription>
                Integration status of frontend, backend, and crypto components
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={checkStatus}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {/* Overall Status */}
          <Alert className={overallHealth ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}>
            {overallHealth ? (
              <CheckCircle className="h-4 w-4 text-green-600" />
            ) : (
              <AlertCircle className="h-4 w-4 text-red-600" />
            )}
            <AlertDescription className={overallHealth ? "text-green-800" : "text-red-800"}>
              {overallHealth 
                ? "Decentralized system is fully operational" 
                : "System has issues that need attention"}
            </AlertDescription>
          </Alert>

          {/* Component Status */}
          {status && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="flex flex-col items-center p-3 border rounded-lg">
                <Database className="h-6 w-6 mb-2 text-gray-600" />
                {getStatusBadge(status.database, "Database")}
              </div>
              
              <div className="flex flex-col items-center p-3 border rounded-lg">
                <Key className="h-6 w-6 mb-2 text-gray-600" />
                {getStatusBadge(status.crypto, "Crypto")}
              </div>
              
              <div className="flex flex-col items-center p-3 border rounded-lg">
                <Shield className="h-6 w-6 mb-2 text-gray-600" />
                {getStatusBadge(status.rings, "Rings")}
              </div>
              
              <div className="flex flex-col items-center p-3 border rounded-lg">
                <Coins className="h-6 w-6 mb-2 text-gray-600" />
                {getStatusBadge(status.tokens, "Tokens")}
              </div>
              
              <div className="flex flex-col items-center p-3 border rounded-lg">
                <Vote className="h-6 w-6 mb-2 text-gray-600" />
                {getStatusBadge(status.voting, "Voting")}
              </div>
            </div>
          )}

          {/* Requirements Status */}
          {requirements && (
            <div className="space-y-3">
              <h4 className="font-medium text-sm text-gray-700">System Requirements</h4>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="flex items-center justify-between">
                  <span>Cryptographic Keys:</span>
                  {getStatusBadge(requirements.hasKeys, requirements.hasKeys ? "Generated" : "Missing")}
                </div>
                <div className="flex items-center justify-between">
                  <span>Voting Tokens:</span>
                  {getStatusBadge(requirements.hasTokens, `${tokens.length} available`)}
                </div>
                <div className="flex items-center justify-between">
                  <span>Ring Signatures:</span>
                  {getStatusBadge(requirements.hasRings, requirements.hasRings ? "Available" : "None")}
                </div>
                <div className="flex items-center justify-between">
                  <span>Can Vote:</span>
                  {getStatusBadge(requirements.canVote, requirements.canVote ? "Yes" : "No")}
                </div>
              </div>
              
              {requirements.pendingSubmissions > 0 && (
                <div className="text-sm text-gray-600">
                  <strong>{requirements.pendingSubmissions}</strong> submissions pending review
                </div>
              )}
            </div>
          )}

          {/* Action Buttons */}
          {showActions && (
            <div className="space-y-3 pt-4 border-t">
              <div className="flex gap-3">
                <Button
                  onClick={initializeSystem}
                  disabled={isInitializing}
                  className="flex-1"
                >
                  {isInitializing ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Initializing...
                    </>
                  ) : (
                    <>
                      <Settings className="h-4 w-4 mr-2" />
                      Initialize System
                    </>
                  )}
                </Button>
                
                <Button
                  variant="outline"
                  onClick={testVotingFlow}
                  disabled={isLoading}
                  className="flex-1"
                >
                  <Vote className="h-4 w-4 mr-2" />
                  Test Voting
                </Button>
              </div>
              
              <div className="flex gap-3">
                <Button
                  variant="secondary"
                  onClick={async () => {
                    const { clearAll, generateKeyPair } = useCryptoStore.getState();
                    clearAll();
                    await generateKeyPair();
                    await checkStatus();
                    toast.success('Crypto keys regenerated');
                  }}
                  disabled={isLoading}
                  className="flex-1"
                >
                  <Key className="h-4 w-4 mr-2" />
                  Regenerate Keys
                </Button>
                
                <Button
                  variant="secondary"
                  onClick={() => {
                    const { tokens } = useCryptoStore.getState();
                    console.log('Current system state:', {
                      hasKeys: useCryptoStore.getState().hasKeyPair(),
                      tokenCount: tokens.length,
                      status,
                      requirements
                    });
                    toast.info('Check console for debug info');
                  }}
                  className="flex-1"
                >
                  <AlertCircle className="h-4 w-4 mr-2" />
                  Debug Info
                </Button>
              </div>
            </div>
          )}

          {/* Debug Info */}
          {status && (
            <details className="text-xs text-gray-500">
              <summary className="cursor-pointer">Debug Information</summary>
              <pre className="mt-2 p-2 bg-gray-100 rounded overflow-auto">
                {JSON.stringify({ status, requirements, localTokens: tokens.length }, null, 2)}
              </pre>
            </details>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
