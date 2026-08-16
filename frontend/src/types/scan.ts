export interface ScanResult {
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

export interface SecurityHeadersCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: HeaderFinding[];
  remediation: string;
}

export interface HeaderFinding {
  header: string;
  present: boolean;
  value?: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface CookieFlagsCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: CookieFinding[];
  remediation: string;
}

export interface CookieFinding {
  cookieName: string;
  missingFlags: string[];
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface ExposedFilesCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: ExposedFileFinding[];
  remediation: string;
}

export interface ExposedFileFinding {
  path: string;
  accessible: boolean;
  statusCode?: number;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface TLSCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  tlsVersion?: string;
  cipherSuite?: string;
  isModernTLS: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface MixedContentCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  httpResources: string[];
  count: number;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface SubdomainTakeoverCheck {
  status: 'pass' | 'fail' | 'warning';
  score: number;
  findings: SubdomainFinding[];
  remediation: string;
}

export interface SubdomainFinding {
  domain: string;
  cnameTarget?: string;
  vulnerableProvider?: string;
  isVulnerable: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

export interface ScanError {
  error: string;
  details?: string;
}
