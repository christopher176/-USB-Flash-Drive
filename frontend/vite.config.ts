import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies /api to the local scanning agent. Keeping traffic
// same-origin means browsers never perform a cross-origin request to the
// agent at all; the agent independently enforces its Origin/Host allowlists
// and bearer-token checks (defence in depth).
export default defineConfig({
  plugins: [
    react(),
    {
      // Development servers inject an inline HMR/react-refresh preamble, which
      // the production CSP ('script-src self') would block. Relax script-src in
      // dev only; production builds contain no inline scripts and keep the
      // strict policy from index.html.
      name: 'usb-shield-dev-csp',
      transformIndexHtml: {
        order: 'pre',
        handler(html, ctx) {
          if (ctx.server) {
            return html.replace("script-src 'self'",
                                "script-src 'self' 'unsafe-inline'")
          }
          return html
        },
      },
    },
  ],
  server: {
    host: '0.0.0.0',
    port: Number(process.env.VITE_PORT || 3847),
    allowedHosts: true, // preview hosts such as *.e2b.app and localhost
    proxy: {
      '/api': {
        target: process.env.USBSHIELD_AGENT_URL || 'http://127.0.0.1:8765',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    sourcemap: false,
    target: 'es2020',
  },
})
