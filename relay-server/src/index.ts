import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

import config from './config';
import { NearAccountService, getServerConfig } from '@web3authn/passkey/server';
import routes from './routes';

const app: Express = express();

// Create NearAccountService instance
const nearAccountService = new NearAccountService(getServerConfig());

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
  console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);

  nearAccountService.getRelayerAccount().then((relayer) => {
    console.log(`AccountService connected with relayer account: ${relayer.accountId}`)
  }).catch((err: Error) => {
    console.error("AccountService initial check failed (non-blocking server start):", err);
  });
});

// Export for use in routes
export { nearAccountService };