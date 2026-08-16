import React from 'react';

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

interface ReportCardProps {
  result: ScanResult;
}

const getGradeColor = (grade: string): string => {
  const colors: Record<string, string> = {
    A: 'text-green-400 bg-green-500/20 border-green-500',
    B: 'text-blue-400 bg-blue-500/20 border-blue-500',
    C: 'text-yellow-400 bg-yellow-500/20 border-yellow-500',
    D: 'text-orange-400 bg-orange-500/20 border-orange-500',
    F: 'text-red-400 bg-red-500/20 border-red-500',
  };
  return colors[grade] || 'text-gray-400 bg-gray-500/20 border-gray-500';
};

const getSeverityColor = (severity: string): string => {
  const colors: Record<string, string> = {
    high: 'text-red-400 bg-red-500/20 border-red-500',
    medium: 'text-orange-400 bg-orange-500/20 border-orange-500',
    low: 'text-yellow-400 bg-yellow-500/20 border-yellow-500',
    info: 'text-blue-400 bg-blue-500/20 border-blue-500',
  };
  return colors[severity] || 'text-gray-400 bg-gray-500/20 border-gray-500';
};

const getStatusIcon = (status: string): string => {
  const icons: Record<string, string> = {
    pass: '✓',
    fail: '✗',
    warning: '!',
  };
  return icons[status] || '?';
};

const getStatusBadgeClass = (status: string): string => {
  const classes: Record<string, string> = {
    pass: 'bg-green-500/20 text-green-400',
    fail: 'bg-red-500/20 text-red-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
  };
  return classes[status] || 'bg-gray-500/20 text-gray-400';
};

export const ReportCard: React.FC<ReportCardProps> = ({ result }) => {
  const gradeColorClass = getGradeColor(result.grade);

  return (
    <div className="space-y-6">
      {/* Overall Score Card */}
      <div className="card text-center py-8">
        <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full text-5xl font-bold border-4 mb-4 ${gradeColorClass}`}>
          {result.grade}
        </div>
        <h3 className="text-2xl font-bold mb-2">Security Score: {result.overallScore}/100</h3>
        <p className="text-gray-400">Scanned: {new Date(result.timestamp).toLocaleString()}</p>
        <p className="text-gray-400 mt-1">
          URL: <span className="font-mono text-sm">{result.url}</span>
        </p>
      </div>

      {/* Detailed Findings */}
      <div className="card">
        <h3 className="text-xl font-bold mb-4">Detailed Findings</h3>

        {/* Security Headers */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">Security Headers</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.securityHeaders.status)}`}>
              {getStatusIcon(result.checks.securityHeaders.status)} {result.checks.securityHeaders.status.toUpperCase()}
            </span>
          </div>
          <div className="space-y-2">
            {result.checks.securityHeaders.findings.map((finding, idx) => (
              <div key={idx} className={`p-3 rounded-lg border ${getSeverityColor(finding.severity)}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm">{finding.header}</span>
                  {finding.present ? (
                    <span className="text-green-400">✓ Present</span>
                  ) : (
                    <span className="text-red-400">✗ Missing</span>
                  )}
                </div>
                <p className="text-sm mt-1 opacity-80">{finding.description}</p>
                {!finding.present && (
                  <p className="text-xs mt-1">
                    <strong>Fix:</strong> {finding.recommendation}
                  </p>
                )}
              </div>
            ))}
          </div>
          <p className="text-sm text-gray-400 mt-2">
            <strong>Remediation:</strong> {result.checks.securityHeaders.remediation}
          </p>
        </div>

        {/* Cookie Flags */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">Cookie Security</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.cookieFlags.status)}`}>
              {getStatusIcon(result.checks.cookieFlags.status)} {result.checks.cookieFlags.status.toUpperCase()}
            </span>
          </div>
          {result.checks.cookieFlags.findings.length > 0 ? (
            <div className="space-y-2">
              {result.checks.cookieFlags.findings.map((finding, idx) => (
                <div key={idx} className={`p-3 rounded-lg border ${getSeverityColor(finding.severity)}`}>
                  <div className="font-mono text-sm">{finding.cookieName}</div>
                  <p className="text-sm mt-1">
                    Missing flags: <span className="text-red-400">{finding.missingFlags.join(', ')}</span>
                  </p>
                  <p className="text-xs mt-1">
                    <strong>Fix:</strong> {finding.recommendation}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-green-400">All cookies have proper security flags.</p>
          )}
          <p className="text-sm text-gray-400 mt-2">
            <strong>Remediation:</strong> {result.checks.cookieFlags.remediation}
          </p>
        </div>

        {/* Exposed Files */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">Exposed Sensitive Files</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.exposedFiles.status)}`}>
              {getStatusIcon(result.checks.exposedFiles.status)} {result.checks.exposedFiles.status.toUpperCase()}
            </span>
          </div>
          <div className="space-y-2">
            {result.checks.exposedFiles.findings.map((finding, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border ${
                  finding.accessible
                    ? 'bg-red-500/20 text-red-400 border-red-500'
                    : 'bg-green-500/20 text-green-400 border-green-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm">{finding.path}</span>
                  {finding.accessible ? (
                    <span className="text-red-400">⚠ ACCESSIBLE</span>
                  ) : (
                    <span className="text-green-400">✓ Protected</span>
                  )}
                </div>
                {finding.accessible && (
                  <p className="text-xs mt-1">
                    <strong>Fix:</strong> {finding.recommendation}
                  </p>
                )}
              </div>
            ))}
          </div>
          <p className="text-sm text-gray-400 mt-2">
            <strong>Remediation:</strong> {result.checks.exposedFiles.remediation}
          </p>
        </div>

        {/* TLS Grade */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">TLS Configuration</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.tlsGrade.status)}`}>
              {getStatusIcon(result.checks.tlsGrade.status)} {result.checks.tlsGrade.status.toUpperCase()}
            </span>
          </div>
          <div className={`p-3 rounded-lg border ${getSeverityColor(result.checks.tlsGrade.severity)}`}>
            <p>
              <strong>TLS Version:</strong> {result.checks.tlsGrade.tlsVersion || 'Unknown'}
            </p>
            <p>
              <strong>Cipher Suite:</strong> {result.checks.tlsGrade.cipherSuite || 'Unknown'}
            </p>
            <p className="mt-2">{result.checks.tlsGrade.description}</p>
            <p className="text-xs mt-1">
              <strong>Recommendation:</strong> {result.checks.tlsGrade.recommendation}
            </p>
          </div>
        </div>

        {/* Mixed Content */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">Mixed Content</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.mixedContent.status)}`}>
              {getStatusIcon(result.checks.mixedContent.status)} {result.checks.mixedContent.status.toUpperCase()}
            </span>
          </div>
          {result.checks.mixedContent.count > 0 ? (
            <div className="p-3 rounded-lg border border-red-500 bg-red-500/20">
              <p className="text-red-400">
                Found {result.checks.mixedContent.count} insecure HTTP resource(s):
              </p>
              <ul className="list-disc list-inside text-sm mt-2 text-red-300">
                {result.checks.mixedContent.httpResources.slice(0, 10).map((resource, idx) => (
                  <li key={idx} className="font-mono text-xs">
                    {resource}
                  </li>
                ))}
              </ul>
              <p className="text-xs mt-2">
                <strong>Fix:</strong> {result.checks.mixedContent.recommendation}
              </p>
            </div>
          ) : (
            <p className="text-green-400">No mixed content detected. All resources use HTTPS.</p>
          )}
        </div>

        {/* Subdomain Takeover */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold">Subdomain Takeover Risk</h4>
            <span className={`px-3 py-1 rounded-full text-sm ${getStatusBadgeClass(result.checks.subdomainTakeover.status)}`}>
              {getStatusIcon(result.checks.subdomainTakeover.status)} {result.checks.subdomainTakeover.status.toUpperCase()}
            </span>
          </div>
          {result.checks.subdomainTakeover.findings.length > 0 ? (
            <div className="space-y-2">
              {result.checks.subdomainTakeover.findings.map((finding, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border ${
                    finding.isVulnerable
                      ? 'bg-red-500/20 text-red-400 border-red-500'
                      : 'bg-green-500/20 text-green-400 border-green-500'
                  }`}
                >
                  <div className="font-mono text-sm">{finding.domain}</div>
                  {finding.isVulnerable ? (
                    <>
                      <p className="text-sm mt-1">
                        Points to vulnerable provider: <strong>{finding.vulnerableProvider}</strong>
                      </p>
                      <p className="text-sm">
                        CNAME: {finding.cnameTarget || 'N/A'}
                      </p>
                      <p className="text-xs mt-1">
                        <strong>Fix:</strong> {finding.recommendation}
                      </p>
                    </>
                  ) : (
                    <p className="text-green-400">No vulnerability detected</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-green-400">No CNAME records pointing to vulnerable providers found.</p>
          )}
          <p className="text-sm text-gray-400 mt-2">
            <strong>Remediation:</strong> {result.checks.subdomainTakeover.remediation}
          </p>
        </div>
      </div>
    </div>
  );
};

export default ReportCard;
