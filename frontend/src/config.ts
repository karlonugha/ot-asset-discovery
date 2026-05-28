/**
 * Application configuration derived from environment variables.
 *
 * In production (Vercel), set VITE_API_BASE_URL to your Railway/Render backend URL.
 * In development, relative paths proxy through Vite's dev server.
 */

export const config = {
  /** Base URL for REST API calls. Empty string means relative (same origin). */
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? '',

  /** Base URL for WebSocket connections. */
  wsBaseUrl: import.meta.env.VITE_WS_BASE_URL ?? 'ws://localhost:8000',

  /** Whether the app is running in demo mode (no backend required). */
  isDemoMode: import.meta.env.VITE_DEMO_MODE === 'true',
} as const;
