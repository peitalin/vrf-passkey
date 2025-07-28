import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

import { NearAccountService, getServerConfig, type CreateAccountAndRegisterRequest } from '@web3authn/passkey/server';

const app: Express = express();

// Simple configuration
const config = {
  port: process.env.PORT || 3000,
  expectedOrigin: process.env.EXPECTED_ORIGIN || 'https://example.localhost'
};

// Create NearAccountService instance
const nearAccountService = new NearAccountService(getServerConfig());

// Middleware
app.use(express.json());
app.use(cors({
  origin: config.expectedOrigin,
  credentials: true,
}));

// Health check route
app.get('/', (req: Request, res: Response) => {
  const timestamp = new Date().toISOString();
  console.log(`Health check requested at ${timestamp}`);
  res.send(`Web3 Authn Relay Server is running! (${timestamp})`);
});

// Account creation route
app.post('/create_account_and_register_user', async (req: Request<any, any, CreateAccountAndRegisterRequest>, res: Response) => {
  try {
    console.log('POST /create_account_and_register_user', {
      account: req.body.new_account_id,
      publicKey: req.body.new_public_key?.substring(0, 20) + '...',
      hasVrfData: !!req.body.vrf_data,
      hasWebAuthnRegistration: !!req.body.webauthn_registration
    });

    const { new_account_id, new_public_key, vrf_data, webauthn_registration, deterministic_vrf_public_key } = req.body;

    // Validate required parameters
    if (!new_account_id || typeof new_account_id !== 'string') {
      throw new Error('Missing or invalid new_account_id');
    }
    if (!new_public_key || typeof new_public_key !== 'string') {
      throw new Error('Missing or invalid new_public_key');
    }
    if (!vrf_data || typeof vrf_data !== 'object') {
      throw new Error('Missing or invalid vrf_data');
    }
    if (!webauthn_registration || typeof webauthn_registration !== 'object') {
      throw new Error('Missing or invalid webauthn_registration');
    }

    // Call the atomic contract function via accountService
    const result = await nearAccountService.createAccountAndRegisterUser({
      new_account_id,
      new_public_key,
      vrf_data,
      webauthn_registration,
      deterministic_vrf_public_key
    });

    // Return the result directly - don't throw if unsuccessful
    if (result.success) {
      res.status(200).json(result);
    } else {
      // Return error response with appropriate HTTP status code
      console.error('Atomic account creation and registration failed:', result.error);
      res.status(400).json(result);
    }

  } catch (error: any) {
    console.error('Atomic account creation and registration failed:', error.message);
    res.status(500).json({
      success: false,
      error: error.message || 'Unknown server error'
    });
  }
});

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