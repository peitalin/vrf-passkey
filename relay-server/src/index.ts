import express, { Express, Request, Response } from 'express';
import {
  NearAccountService,
  type CreateAccountAndRegisterRequest,
  type CreateAccountAndRegisterResult,
} from '@web3authn/passkey/server';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

const config = {
  port: 3000,
  expectedOrigin: 'https://example.localhost', // Replace with your frontend origin
};
// Create NearAccountService instance
const nearAccountService = new NearAccountService({
  // new accounts with be created with this account: e.g. bob.{relayer-account-id}.near
  // you can make it the same account as the webauthn contract id.
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID!,
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY!,
  webAuthnContractId: 'web3-authn-v2.testnet',
  nearRpcUrl: 'https://rpc.testnet.near.org',
  networkId: 'testnet',
  defaultInitialBalance: '50000000000000000000000', // 0.05 NEAR
  defaultCreateAccountAndRegisterGas: '120000000000000', // 120 TGas
});

const app: Express = express();
// Middleware
app.use(express.json());
app.use(cors({
  origin: config.expectedOrigin,
  credentials: true,
}));
// Global error handler
app.use((err: Error, req: Request, res: Response) => {
  console.error(err.stack);
  res.status(500).send('Internal NearAccountService error');
});

// Account creation route
app.post(
  '/create_account_and_register_user',
  async (req: Request<CreateAccountAndRegisterRequest>, res: Response<CreateAccountAndRegisterResult>) => {
    try {
      const {
        new_account_id,
        new_public_key,
        vrf_data,
        webauthn_registration,
        deterministic_vrf_public_key
      } = req.body;

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
  }
);

app.listen(config.port, () => {
  console.log(`Server listening on http://localhost:${config.port}`);
  console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);

  nearAccountService.getRelayerAccount().then((relayer) => {
    console.log(`AccountService connected with relayer account: ${relayer.accountId}`)
  }).catch((err: Error) => {
    console.error("AccountService initial check failed (non-blocking server start):", err);
  });
});