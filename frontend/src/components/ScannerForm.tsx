import React, { useState } from 'react';

interface ScannerFormProps {
  onScan: (url: string) => void;
  isLoading: boolean;
  initialUrl?: string;
}

export const ScannerForm: React.FC<ScannerFormProps> = ({ onScan, isLoading, initialUrl = '' }) => {
  const [url, setUrl] = useState(initialUrl);
  const [error, setError] = useState('');

  const validateUrl = (inputUrl: string): boolean => {
    try {
      const parsed = new URL(inputUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        setError('URL must start with http:// or https://');
        return false;
      }
      return true;
    } catch {
      setError('Please enter a valid URL');
      return false;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      setError('Please enter a URL');
      return;
    }

    if (validateUrl(trimmedUrl)) {
      onScan(trimmedUrl);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="card mb-8">
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1">
          <label htmlFor="url-input" className="block text-sm font-medium text-gray-300 mb-2">
            Website URL
          </label>
          <input
            type="text"
            id="url-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="input-field"
            disabled={isLoading}
            aria-label="Website URL to scan"
          />
          {error && (
            <p className="text-red-400 text-sm mt-2">{error}</p>
          )}
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            id="scan-button"
            className="btn-primary w-full md:w-auto"
            disabled={isLoading}
            aria-label={isLoading ? 'Scanning...' : 'Scan Website'}
          >
            {isLoading ? (
              <>
                <span className="inline-block animate-spin mr-2">⟳</span>
                Scanning...
              </>
            ) : (
              'Scan Website'
            )}
          </button>
        </div>
      </div>
    </form>
  );
};

export default ScannerForm;
