import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import ScannerForm from '../components/ScannerForm';
import ReportCard from '../components/ReportCard';

interface ScanResult {
  url: string;
  overallScore: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  timestamp: string;
  checks: {
    securityHeaders: SecurityHeadersCheck;
    cookieFlags: CookieFlagsCheck;
    exposedFiles: ExposedFilesCheck;
    tlsGrade: TLSCheck;
    mixedContent: MixedContentCheck;
    subdomainTakeover: SubdomainTakeoverCheck;
  };
}

interface SecurityHeadersCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: HeaderFinding[];
  remediation: string;
}

interface HeaderFinding {
  header: string;
  present: boolean;
  value?: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface CookieFlagsCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: CookieFinding[];
  remediation: string;
}

interface CookieFinding {
  cookieName: string;
  missingFlags: string[];
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface ExposedFilesCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: ExposedFileFinding[];
  remediation: string;
}

interface ExposedFileFinding {
  path: string;
  accessible: boolean;
  statusCode?: number;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface TLSCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  tlsVersion?: string;
  cipherSuite?: string;
  isModernTLS: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface MixedContentCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  httpResources: string[];
  count: number;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface SubdomainTakeoverCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: SubdomainFinding[];
  remediation: string;
}

interface SubdomainFinding {
  domain: string;
  cnameTarget?: string;
  vulnerableProvider?: string;
  isVulnerable: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

interface ScanError {
  error: string;
  details?: string;
}

type ScanResponse = ScanResult | ScanError;

const App: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [currentUrl, setCurrentUrl] = useState('');
  const [workerUrl, setWorkerUrl] = useState('http://localhost:8787');

  useEffect(() => {
    // Get worker URL from window or data attribute
    const appDiv = document.getElementById('app');
    const dataWorkerUrl = appDiv?.getAttribute('data-worker-url');
    if (dataWorkerUrl) {
      setWorkerUrl(dataWorkerUrl);
    } else if ((window as typeof window & { WORKER_URL?: string }).WORKER_URL) {
      setWorkerUrl((window as typeof window & { WORKER_URL?: string }).WORKER_URL!);
    }
  }, []);

  const handleScan = async (url: string) => {
    setIsLoading(true);
    setCurrentUrl(url);
    setResult(null);

    try {
      const response = await fetch(`${workerUrl}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An unexpected error occurred';
      setResult({ error: 'Scan failed', details: errorMessage });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <ScannerForm 
        onScan={handleScan} 
        isLoading={isLoading} 
        initialUrl={currentUrl} 
      />

      {isLoading && (
        <div className="card text-center py-12">
          <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Scanning website security...</p>
          <p className="text-gray-500 text-sm mt-2">This may take up to 30 seconds</p>
        </div>
      )}

      {result && !isLoading && (
        <>
          {'error' in result && !('grade' in result) ? (
            <div className="card border-red-500/50">
              <h3 className="text-xl font-semibold text-red-400 mb-2">Scan Failed</h3>
              <p className="text-gray-300">{result.error}</p>
              {result.details && (
                <p className="text-gray-500 text-sm mt-2">{result.details}</p>
              )}
            </div>
          ) : (
            <ReportCard result={result as ScanResult} />
          )}
        </>
      )}
    </div>
  );
};

// Hydrate the app
const rootElement = document.getElementById('app');
if (rootElement) {
  const root = createRoot(rootElement);
  root.render(<App />);
}

export default App;
