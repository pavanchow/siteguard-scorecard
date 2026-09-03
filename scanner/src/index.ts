import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { performSecurityScan } from './scanner';

// Create Hono app
const app = new Hono();

// Enable CORS for frontend access
app.use('/*', cors({
  origin: ['*', 'http://localhost:4321', 'https://*.github.io'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  maxAge: 86400,
}));

// Health check endpoint
app.get('/', (c) => {
  return c.json({
    name: 'SiteGuard Scorecard Scanner API',
    version: '1.0.0',
    status: 'healthy',
    endpoints: {
      scan: '/scan',
    },
  });
});

// Health check
app.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Main scan endpoint
app.post('/scan', async (c) => {
  try {
    // Parse request body
    const body = await c.req.json<{ url?: string }>();
    
    if (!body.url) {
      return c.json(
        { error: 'Missing URL parameter', details: 'Please provide a URL in the request body' },
        400
      );
    }

    const targetUrl = body.url.trim();

    // Validate URL format
    try {
      const parsedUrl = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch {
      return c.json(
        { 
          error: 'Invalid URL format', 
          details: 'Please provide a valid URL starting with http:// or https://' 
        },
        400
      );
    }

    // Perform security scan
    const result = await performSecurityScan(targetUrl);

    return c.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    return c.json(
      { 
        error: 'Scan failed', 
        details: errorMessage 
      },
      500
    );
  }
});

// Handle OPTIONS preflight requests
app.options('/scan', (c) => {
  return c.body(null, 204);
});

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not Found', details: `Endpoint ${c.req.path} not found` }, 404);
});

export default app;
