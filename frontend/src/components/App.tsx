import React, { useState } from 'react';
import ScannerForm from './ScannerForm';
import ReportCard from './ReportCard';
import type { ScanResult, ScanError } from '../types/scan';

type ScanResponse = ScanResult | ScanError;

interface AppProps {
  workerUrl?: string;
}

const App: React.FC<AppProps> = ({ workerUrl = 'http://localhost:8787' }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [currentUrl, setCurrentUrl] = useState('');

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

      const data = (await response.json().catch(() => ({
        error: 'Invalid response',
        details: `HTTP ${response.status}: ${response.statusText}`,
      }))) as ScanResponse;

      if (!response.ok) {
        const errData = data as ScanError;
        throw new Error(errData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

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
      <ScannerForm onScan={handleScan} isLoading={isLoading} initialUrl={currentUrl} />

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
              {result.details && <p className="text-gray-500 text-sm mt-2">{result.details}</p>}
            </div>
          ) : (
            <ReportCard result={result as ScanResult} />
          )}
        </>
      )}
    </div>
  );
};

export default App;
