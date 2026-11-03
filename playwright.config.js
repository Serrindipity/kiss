import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  workers: 1,
  timeout: 30000,
  use: { baseURL: 'http://127.0.0.1:8765', viewport: { width: 1505, height: 1045 } },
  webServer: {
    command: '.venv/bin/python scripts/qa_server.py',
    url: 'http://127.0.0.1:8765',
    reuseExistingServer: false,
    timeout: 15000,
  },
});
