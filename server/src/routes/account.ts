import { Router, Request, Response } from 'express';
import { PublicKey } from '@near-js/crypto';

import config from '../config';
import { userOperations, authenticatorOperations } from '../database';
import { nearClient } from '../nearService';

const router = Router();

// Associate a client-generated NEAR public key with a user account
router.post('/api/associate-account-pk', async (req: Request, res: Response) => {
  const { username, derpAccountId, clientNearPublicKey } = req.body;

  if (!username || !derpAccountId || !clientNearPublicKey) {
    return res.status(400).json({
      error: 'Username, derpAccountId, and clientNearPublicKey are required.'
    });
  }

  // Validate that derpAccountId is a subaccount of the relayer account
  // TODO: lift this restriction if possible so users can create to-level accounts.
  // Only certain accounts on NEAR are allowed to create top-level accounts.
  if (!derpAccountId.endsWith(`.${config.relayerAccountId}`)) {
    return res.status(400).json({
      error: `Invalid derpAccountId: '${derpAccountId}'. Account must be a subaccount of the relayer '${config.relayerAccountId}'. (e.g., yourname.${config.relayerAccountId})`
    });
  }

  try {
    const user = userOperations.findByUsername(username);
    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found.` });
    }

    if (user.derpAccountId !== derpAccountId) {
      console.warn(`Potential derpAccountId mismatch for ${username}. Server expected: ${user.derpAccountId}, client provided: ${derpAccountId}. Proceeding with client provided ID.`);
    }

    let nearPublicKeyToRegister: PublicKey;
    try {
      nearPublicKeyToRegister = PublicKey.fromString(clientNearPublicKey);
    } catch (keyError: any) {
      console.error("Invalid clientNearPublicKey format:", clientNearPublicKey, keyError);
      return res.status(400).json({
        error: `Invalid clientNearPublicKey format: ${keyError.message}`
      });
    }

    // Check if account exists, create if not
    try {
      const accountExists = await nearClient.checkAccountExists(derpAccountId);
      if (!accountExists) {
        console.log(`Account ${derpAccountId} does not exist. Attempting to create...`);
        const creationResult = await nearClient.createAccount(derpAccountId, clientNearPublicKey);
        if (!creationResult.success) {
          console.error(`Failed to create account ${derpAccountId}:`, creationResult.message, creationResult.error);
          return res.status(500).json({
            success: false,
            error: `Failed to automatically create account '${derpAccountId}'.`,
            details: creationResult,
          });
        }
        console.log(`Account ${derpAccountId} created successfully.`);
      } else {
        console.log(`Account ${derpAccountId} already exists.`);
      }
    } catch (checkOrCreateError: any) {
      console.error(`Error during account existence check or creation for ${derpAccountId}:`, checkOrCreateError);
      return res.status(500).json({
        success: false,
        error: `Error during account check/creation for '${derpAccountId}': ${checkOrCreateError.message}`
      });
    }

    // Update authenticator with client-managed key
    const updateResult = authenticatorOperations.updateClientManagedKey(user.id, clientNearPublicKey);
    if (updateResult.changes === 0) {
      console.warn(`No authenticator found for user ${username} to associate clientManagedNearPublicKey, or no update made.`);
    }

    return res.json({
      success: true,
      message: `Client NEAR public key ${clientNearPublicKey} associated with ${derpAccountId}. Account checked/created and PK registered on-chain.`,
    });

  } catch (error: any) {
    console.error('Error in /api/associate-account-pk:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to associate client public key.'
    });
  }
});

// Create a NEAR account using the relay account
router.post('/api/create-account', async (req: Request, res: Response) => {
  const { accountId, publicKey, isTestnet } = req.body;

  if (!accountId || !publicKey) {
    return res.status(400).json({ error: 'accountId and publicKey are required.' });
  }

  console.log("/api/create-account: creating account:", accountId, "with public key", publicKey);

  try {
    const result = await nearClient.createAccount(accountId, publicKey);
    console.log("Account creation result from nearClient:", result);

    if (result.success) {
      return res.json({
        success: true,
        message: result.message || 'Account created successfully.',
        result: result.result
      });
    } else {
      return res.status(500).json({
        success: false,
        error: result.message || 'Account creation failed via nearClient.',
        details: result.error
      });
    }

  } catch (error: any) {
    console.error("Error in /api/create-account endpoint:", error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to create account due to an unexpected server error in endpoint.'
    });
  }
});

export default router;