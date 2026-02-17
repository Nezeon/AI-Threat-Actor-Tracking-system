import { Request, Response, NextFunction } from 'express';

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): void {
  console.error('Error:', err.message);

  // Only log stack traces in development
  if (process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  }

  // Don't leak internal error details (DB errors, API key errors) in production
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message || 'Internal server error';

  res.status(500).json({ message });
}
