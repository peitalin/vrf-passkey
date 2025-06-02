import dotenv from 'dotenv';
dotenv.config(); // Load environment variables at the very beginning

import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';

import config from './config';
import { initDB } from './database';
import { nearClient } from './nearService';
import routes from './routes';

const app: Express = express();

// Initialize database
initDB();

// Middleware
app.use(express.json());
app.use(cors({
  origin: config.expectedOrigin,
  credentials: true,
}));

// Mount all routes
app.use('/', routes);

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(config.port, () => {
  console.log(`Server listening on http://localhost:${config.port}`);
  console.log(`Relying Party ID: ${config.rpID}`);
  console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
  console.log(`Using Contract Method: ${config.useContractMethod ? 'NEAR Contract' : 'SimpleWebAuthn'}`);

  nearClient.getTrustedRelayer().then((relayer: string) => {
    console.log(`NearClient connected, PasskeyController trusted relayer: ${relayer}`)
  }).catch((err: Error) => {
    console.error("NearClient initial check failed (non-blocking server start):", err);
  });
});