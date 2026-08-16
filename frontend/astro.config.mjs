import react from '@astrojs/react';

/** @type {import('astro').Config} */
export default {
  integrations: [react()],
  output: 'static',
};
