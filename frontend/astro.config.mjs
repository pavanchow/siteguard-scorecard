import react from '@astrojs/react';

/** @type {import('astro').Config} */
export default {
  // GitHub Pages project site: https://pavanchow.github.io/siteguard-scorecard/
  site: 'https://pavanchow.github.io',
  base: '/siteguard-scorecard',
  integrations: [react()],
  output: 'static',
};
