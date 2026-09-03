import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  calculateGrade,
  checkSecurityHeaders,
  checkCookieFlags,
  checkExposedFiles,
  checkMixedContent,
  checkTLS,
  performSecurityScan,
} from './scanner';

// Minimal Response stub good enough for the scanner's usage.
function makeResponse(opts: {
  status?: number;
  headers?: Record<string, string>;
  setCookies?: string[];
  body?: string;
}) {
  const headers = new Headers(opts.headers ?? {});
  for (const c of opts.setCookies ?? []) {
    headers.append('set-cookie', c);
  }
  const status = opts.status ?? 200;
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    text: async () => opts.body ?? '',
    json: async () => JSON.parse(opts.body ?? '{}'),
  } as unknown as Response;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('calculateGrade', () => {
  it('maps score ranges to letter grades', () => {
    expect(calculateGrade(100)).toBe('A');
    expect(calculateGrade(90)).toBe('A');
    expect(calculateGrade(89)).toBe('B');
    expect(calculateGrade(80)).toBe('B');
    expect(calculateGrade(79)).toBe('C');
    expect(calculateGrade(70)).toBe('C');
    expect(calculateGrade(69)).toBe('D');
    expect(calculateGrade(60)).toBe('D');
    expect(calculateGrade(59)).toBe('F');
    expect(calculateGrade(0)).toBe('F');
  });
});

describe('checkSecurityHeaders', () => {
  it('scores 100 and passes when all critical headers are present', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        makeResponse({
          headers: {
            'strict-transport-security': 'max-age=31536000; includeSubDomains',
            'content-security-policy': "default-src 'self'",
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
          },
        })
      )
    );

    const result = await checkSecurityHeaders('https://example.com');
    expect(result.score).toBe(100);
    expect(result.status).toBe('pass');
    expect(result.findings.every((f) => f.present)).toBe(true);
  });

  it('fails with score 0 when no headers are present', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => makeResponse({ headers: {} })));

    const result = await checkSecurityHeaders('https://example.com');
    expect(result.score).toBe(0);
    expect(result.status).toBe('fail');
    expect(result.findings.some((f) => f.present)).toBe(false);
  });

  it('warns when only some headers are present', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        makeResponse({
          headers: {
            'strict-transport-security': 'max-age=31536000',
            'x-frame-options': 'SAMEORIGIN',
          },
        })
      )
    );

    const result = await checkSecurityHeaders('https://example.com');
    expect(result.score).toBe(50);
    expect(result.status).toBe('warning');
  });

  it('returns a failing result when the fetch throws', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network'); }));

    const result = await checkSecurityHeaders('https://example.com');
    expect(result.status).toBe('fail');
    expect(result.score).toBe(0);
  });
});

describe('checkCookieFlags', () => {
  it('passes when no cookies are set', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => makeResponse({ setCookies: [] })));

    const result = await checkCookieFlags('https://example.com');
    expect(result.score).toBe(100);
    expect(result.status).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });

  it('flags a cookie missing all security flags as high severity', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => makeResponse({ setCookies: ['session=abc; Path=/'] }))
    );

    const result = await checkCookieFlags('https://example.com');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].cookieName).toBe('session');
    expect(result.findings[0].missingFlags).toEqual(
      expect.arrayContaining(['Secure', 'HttpOnly', 'SameSite'])
    );
    expect(result.findings[0].severity).toBe('high');
    expect(result.score).toBe(80);
  });

  it('passes a cookie that carries all required flags', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        makeResponse({
          setCookies: ['session=abc; Path=/; Secure; HttpOnly; SameSite=Strict'],
        })
      )
    );

    const result = await checkCookieFlags('https://example.com');
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
    expect(result.status).toBe('pass');
  });
});

describe('checkExposedFiles', () => {
  it('passes when every sensitive path returns non-200', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => makeResponse({ status: 404 })));

    const result = await checkExposedFiles('https://example.com');
    expect(result.score).toBe(100);
    expect(result.status).toBe('pass');
    expect(result.findings.every((f) => !f.accessible)).toBe(true);
  });

  it('fails and marks the exposed file when a path returns 200', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        return makeResponse({ status: url.endsWith('/.env') ? 200 : 404 });
      })
    );

    const result = await checkExposedFiles('https://example.com');
    expect(result.status).toBe('fail');
    const env = result.findings.find((f) => f.path === '/.env');
    expect(env?.accessible).toBe(true);
    expect(result.score).toBe(75); // one exposed file => 100 - 25
  });
});

describe('checkMixedContent', () => {
  it('detects http resources embedded in an https page', async () => {
    const html = `<html><head>
      <script src="http://cdn.example.com/a.js"></script>
      <img src="http://img.example.com/x.png">
    </head></html>`;
    vi.stubGlobal('fetch', vi.fn(async () => makeResponse({ body: html })));

    const result = await checkMixedContent('https://example.com');
    expect(result.count).toBeGreaterThanOrEqual(2);
    expect(result.status).toBe('fail');
    expect(result.httpResources).toContain('http://cdn.example.com/a.js');
  });

  it('passes a clean page with no http resources', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        makeResponse({ body: '<html><body><a href="https://ok.com">ok</a></body></html>' })
      )
    );

    const result = await checkMixedContent('https://example.com');
    expect(result.count).toBe(0);
    expect(result.status).toBe('pass');
    expect(result.score).toBe(100);
  });
});

describe('checkTLS', () => {
  it('fails immediately for http urls', async () => {
    const result = await checkTLS('http://example.com');
    expect(result.status).toBe('fail');
    expect(result.isModernTLS).toBe(false);
    expect(result.score).toBe(0);
  });

  it('passes for a reachable https url', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => makeResponse({ status: 200 })));
    const result = await checkTLS('https://example.com');
    expect(result.status).toBe('pass');
    expect(result.isModernTLS).toBe(true);
    expect(result.score).toBe(100);
  });
});

describe('performSecurityScan', () => {
  it('rejects an invalid url', async () => {
    await expect(performSecurityScan('not-a-url')).rejects.toThrow(/Invalid URL/);
  });

  it('rejects an unsupported protocol', async () => {
    await expect(performSecurityScan('ftp://example.com')).rejects.toThrow(/Invalid URL/);
  });

  it('produces a fully-formed graded scan result', async () => {
    // Fully-secured mock so scoring is deterministic and high.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url.includes('cloudflare-dns.com')) {
          return makeResponse({ body: JSON.stringify({ Status: 0 }) });
        }
        return makeResponse({
          status: 404, // sensitive paths not accessible
          headers: {
            'strict-transport-security': 'max-age=31536000; includeSubDomains',
            'content-security-policy': "default-src 'self'",
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
          },
          body: '<html><body>clean</body></html>',
        });
      })
    );

    const result = await performSecurityScan('https://example.com');
    expect(result.url).toContain('example.com');
    expect(result.grade).toMatch(/^[A-F]$/);
    expect(result.overallScore).toBeGreaterThanOrEqual(0);
    expect(result.overallScore).toBeLessThanOrEqual(100);
    expect(result.checks).toHaveProperty('securityHeaders');
    expect(result.checks).toHaveProperty('cookieFlags');
    expect(result.checks).toHaveProperty('exposedFiles');
    expect(result.checks).toHaveProperty('tlsGrade');
    expect(result.checks).toHaveProperty('mixedContent');
    expect(result.checks).toHaveProperty('subdomainTakeover');
    // With a fully-secured mock the grade should be top marks.
    expect(result.grade).toBe('A');
  });
});
