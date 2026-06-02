import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { TanStackRouterVite } from '@tanstack/router-plugin/vite'
import path from 'node:path'
import { aegisApiPlugin } from './vite-plugin-aegis-api'

export default defineConfig({
  plugins: [
    aegisApiPlugin(),
    TanStackRouterVite({ routesDirectory: './src/routes', generatedRouteTree: './src/routeTree.gen.ts' }),
    react(),
  ],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
})
