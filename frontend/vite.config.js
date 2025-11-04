import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // optional: configure a base if you host under a subpath:
  // base: '/your-base-path/',
  resolve: {
    alias: {
      // example if you used src/ absolute imports like `import X from 'src/...';`
      '@': '/src'
    }
  },
  server: {
    host:'0.0.0.0',
    port: 3000 ,
    open: false, 
  },
});
