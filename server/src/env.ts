import path from 'path';
import { fileURLToPath } from 'url';

// In production (Render, etc.), env vars are injected by the platform — no .env file exists.
// Only load .env file in development.
if (process.env.NODE_ENV !== 'production') {
  const dotenv = await import('dotenv');
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  dotenv.config({ path: path.resolve(__dirname, '../../.env') });
}
