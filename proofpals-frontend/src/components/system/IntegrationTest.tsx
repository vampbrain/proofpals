// src/components/system/IntegrationTest.tsx
import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  Play, 
  RefreshCw,
  Database,
  Key,
  Shield,
  Vote,
  Network,
  Lock
} from 'lucide-react';
import { decentralizedSystem, SystemIntegrationStatus } from '@/lib/integration/decentralizedSystem';
import { toast } from 'sonner';

interface TestResult {
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  message?: string;
  details?: any;
}

export function IntegrationTest() {
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [systemStatus, setSystemStatus] = useState<SystemIntegrationStatus | null>(null);
  const [testResults, setTestResults] = useState<TestResult[]>([
    { name: 'Crypto Initialization', status: 'pending' },
    { name: 'Backend Connectivity', status: 'pending' },
    { name: 'Ring Signatures', status: 'pending' },
    { name: 'Voting Endpoints', status: 'pending' },
    { name: 'End-to-End Flow', status: 'pending' },
    { name: 'Anonymity Preservation', status: 'pending' }
  ]);

  const updateTestResult = (name: string, status: TestResult['status'], message?: string, details?: any) => {
    setTestResults(prev => prev.map(test => 
      test.name === name ? { ...test, status, message, details } : test
    ));
  };

  const runIntegrationTest = async () => {
    setIsRunning(true);
    setProgress(0);
    
    try {
      // Reset all tests to pending
      setTestResults(prev => prev.map(test => ({ ...test, status: 'pending' as const })));

      // Test 1: Initialize System
      updateTestResult('Crypto Initialization', 'running');
      setProgress(10);
      
      const initResult = await decentralizedSystem.initialize();
      setSystemStatus(initResult.status);
      
      if (initResult.status.crypto.wasmLoaded && initResult.status.crypto.keyGeneration) {
        updateTestResult('Crypto Initialization', 'passed', 'Cryptographic keys generated successfully');
      } else {
        updateTestResult('Crypto Initialization', 'failed', 'Failed to initialize crypto components');
      }
      setProgress(20);

      // Test 2: Backend Connectivity
      updateTestResult('Backend Connectivity', 'running');
      if (initResult.status.backend.database) {
        updateTestResult('Backend Connectivity', 'passed', 'Backend API responding correctly');
      } else {
        updateTestResult('Backend Connectivity', 'failed', 'Backend connection issues');
      }
      setProgress(35);

      // Test 3: Ring Signatures
      updateTestResult('Ring Signatures', 'running');
      if (initResult.status.crypto.ringSignatures) {
        updateTestResult('Ring Signatures', 'passed', 'Ring signature generation working');
      } else {
        updateTestResult('Ring Signatures', 'failed', 'Ring signature functionality not available');
      }
      setProgress(50);

      // Test 4: Voting Endpoints
      updateTestResult('Voting Endpoints', 'running');
      if (initResult.status.backend.votingEndpoints) {
        updateTestResult('Voting Endpoints', 'passed', 'Voting API endpoints accessible');
      } else {
        updateTestResult('Voting Endpoints', 'failed', 'Voting endpoints not responding');
      }
      setProgress(70);

      // Test 5: End-to-End Flow
      updateTestResult('End-to-End Flow', 'running');
      const e2eResult = await decentralizedSystem.performEndToEndTest();
      
      if (e2eResult.success) {
        updateTestResult('End-to-End Flow', 'passed', 'Complete voting flow operational', e2eResult.results);
      } else {
        updateTestResult('End-to-End Flow', 'failed', 'End-to-end test failed', e2eResult.results);
      }
      setProgress(85);

      // Test 6: Anonymity Preservation
      updateTestResult('Anonymity Preservation', 'running');
      if (initResult.status.integration.anonymityPreserved) {
        updateTestResult('Anonymity Preservation', 'passed', 'Anonymous voting system operational');
      } else {
        updateTestResult('Anonymity Preservation', 'failed', 'Anonymity features not fully functional');
      }
      setProgress(100);

      // Show overall result
      const allPassed = testResults.every(test => test.status === 'passed');
      if (allPassed) {
        toast.success('🎉 All integration tests passed! Decentralized system is fully operational.');
      } else {
        toast.warning('⚠️ Some integration tests failed. System may have limited functionality.');
      }

    } catch (error: any) {
      console.error('Integration test failed:', error);
      toast.error(`Integration test failed: ${error.message}`);
      
      // Mark remaining tests as failed
      setTestResults(prev => prev.map(test => 
        test.status === 'pending' || test.status === 'running' 
          ? { ...test, status: 'failed' as const, message: 'Test interrupted' }
          : test
      ));
    } finally {
      setIsRunning(false);
    }
  };

  const getStatusIcon = (status: TestResult['status']) => {
    switch (status) {
      case 'passed':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-600" />;
      case 'running':
        return <RefreshCw className="h-4 w-4 text-blue-600 animate-spin" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: TestResult['status']) => {
    const variants = {
      passed: 'default',
      failed: 'destructive',
      running: 'secondary',
      pending: 'outline'
    } as const;

    return (
      <Badge variant={variants[status]} className="flex items-center gap-1">
        {getStatusIcon(status)}
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    );
  };

  const getTestIcon = (testName: string) => {
    const icons = {
      'Crypto Initialization': Key,
      'Backend Connectivity': Database,
      'Ring Signatures': Shield,
      'Voting Endpoints': Vote,
      'End-to-End Flow': Network,
      'Anonymity Preservation': Lock
    };
    return icons[testName as keyof typeof icons] || AlertCircle;
  };

  const passedTests = testResults.filter(test => test.status === 'passed').length;
  const totalTests = testResults.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Decentralized System Integration Test
        </CardTitle>
        <CardDescription>
          Comprehensive test of frontend, backend, and crypto integration
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Test Progress */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span>Test Progress</span>
            <span>{passedTests}/{totalTests} tests passed</span>
          </div>
          <Progress value={progress} className="h-2" />
        </div>

        {/* Run Test Button */}
        <Button
          onClick={runIntegrationTest}
          disabled={isRunning}
          className="w-full"
          size="lg"
        >
          {isRunning ? (
            <>
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              Running Tests...
            </>
          ) : (
            <>
              <Play className="h-4 w-4 mr-2" />
              Run Integration Test
            </>
          )}
        </Button>

        {/* Test Results */}
        <div className="space-y-3">
          <h4 className="font-medium text-sm text-gray-700">Test Results</h4>
          {testResults.map((test) => {
            const TestIcon = getTestIcon(test.name);
            return (
              <div key={test.name} className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-3">
                  <TestIcon className="h-5 w-5 text-gray-600" />
                  <div>
                    <div className="font-medium text-sm">{test.name}</div>
                    {test.message && (
                      <div className="text-xs text-gray-500">{test.message}</div>
                    )}
                  </div>
                </div>
                {getStatusBadge(test.status)}
              </div>
            );
          })}
        </div>

        {/* System Status Summary */}
        {systemStatus && (
          <Alert className="border-blue-200 bg-blue-50">
            <Network className="h-4 w-4 text-blue-600" />
            <AlertDescription className="text-blue-900">
              <strong>System Integration Status:</strong>
              <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <div>Frontend: {systemStatus.frontend.cryptoKeys ? '✅' : '❌'} Crypto, {systemStatus.frontend.votingTokens ? '✅' : '❌'} Tokens</div>
                <div>Backend: {systemStatus.backend.database ? '✅' : '❌'} DB, {systemStatus.backend.votingEndpoints ? '✅' : '❌'} Voting</div>
                <div>Crypto: {systemStatus.crypto.wasmLoaded ? '✅' : '❌'} WASM, {systemStatus.crypto.ringSignatures ? '✅' : '❌'} Rings</div>
                <div>Integration: {systemStatus.integration.endToEndVoting ? '✅' : '❌'} E2E, {systemStatus.integration.anonymityPreserved ? '✅' : '❌'} Anonymous</div>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Decentralized Features */}
        <div className="space-y-3">
          <h4 className="font-medium text-sm text-gray-700">Decentralized Features</h4>
          <div className="grid grid-cols-1 gap-2 text-sm">
            {decentralizedSystem.getDecentralizedFeatures().map((feature) => (
              <div key={feature.feature} className="flex items-center justify-between p-2 border rounded">
                <div>
                  <div className="font-medium">{feature.feature}</div>
                  <div className="text-xs text-gray-500">{feature.description}</div>
                </div>
                <Badge variant={feature.enabled ? "default" : "secondary"}>
                  {feature.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
