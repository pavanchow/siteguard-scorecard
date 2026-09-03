import react from '@astrojs/react';

/** @type {import('astro').Config} */
export default {
  // GitHub Pages project site: https://pavanchow.github.io/v1/
  site: 'https://pavanchow.github.io',
  base: '/v1',
  integrations: [react()],
  output: 'static',
};
