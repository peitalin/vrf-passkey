import { Router, Request, Response } from 'express';
import { PublicKey } from '@near-js/crypto';

import config from '../config';
import { userOperations } from '../database';
import { authenticatorService } from '../authenticatorService';
import { nearClient } from '../nearService';

const router = Router();

// Associate a client-generated NEAR public key with a user account
router.post('/api/associate-account-pk', async (req: Request, res: Response) => {
  const { username, nearAccountId, clientNearPublicKey } = req.body;

  if (!username || !nearAccountId || !clientNearPublicKey) {
    return res.status(400).json({
      error: 'Username, nearAccountId, and clientNearPublicKey are required.'
    });
  }

  // Validate that nearAccountId is a subaccount of the relayer account
  // TODO: lift this restriction if possible so users can create to-level accounts.
  // Only certain accounts on NEAR are allowed to create top-level accounts.
  if (!nearAccountId.endsWith(`.${config.relayerAccountId}`)) {
    return res.status(400).json({
      error: `Invalid nearAccountId: '${nearAccountId}'. Account must be a subaccount of the relayer '${config.relayerAccountId}'. (e.g., yourname.${config.relayerAccountId})`
    });
  }

  try {
    const user = userOperations.findByUsername(username);
    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found.` });
    }

    if (user.nearAccountId !== nearAccountId) {
      console.warn(`Potential nearAccountId mismatch for ${username}. Server expected: ${user.nearAccountId}, client provided: ${nearAccountId}. Proceeding with client provided ID.`);
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
      const accountExists = await nearClient.checkAccountExists(nearAccountId);
      if (!accountExists) {
        console.log(`Account ${nearAccountId} does not exist. Attempting to create...`);
        const creationResult = await nearClient.createAccount(nearAccountId, clientNearPublicKey);
        if (!creationResult.success) {
          console.error(`Failed to create account ${nearAccountId}:`, creationResult.message, creationResult.error);
          return res.status(500).json({
            success: false,
            error: `Failed to automatically create account '${nearAccountId}'.`,
            details: creationResult,
          });
        }
        console.log(`Account ${nearAccountId} created successfully.`);
      } else {
        console.log(`Account ${nearAccountId} already exists.`);
      }
    } catch (checkOrCreateError: any) {
      console.error(`Error during account existence check or creation for ${nearAccountId}:`, checkOrCreateError);
      return res.status(500).json({
        success: false,
        error: `Error during account check/creation for '${nearAccountId}': ${checkOrCreateError.message}`
      });
    }

          // Update authenticator with client-managed key
      if (!user.nearAccountId) {
        return res.status(400).json({
          error: 'User has no NEAR account ID. Cannot update authenticator.'
        });
      }

      // Get the latest authenticator for this user
      const latestAuthenticator = await authenticatorService.getLatestByUserId(user.nearAccountId);
      if (latestAuthenticator) {
        const updateResult = await authenticatorService.updateClientManagedKey(
          latestAuthenticator.credentialID,
          clientNearPublicKey,
          user.nearAccountId
        );

        if (!updateResult) {
          console.warn(`Failed to update authenticator for user ${username} with clientManagedNearPublicKey.`);
        } else {
          console.log(`Updated authenticator ${latestAuthenticator.credentialID} with client NEAR public key.`);
        }
      } else {
        console.warn(`No authenticator found for user ${username} to associate clientManagedNearPublicKey.`);
      }

    return res.json({
      success: true,
      message: `Client NEAR public key ${clientNearPublicKey} associated with ${nearAccountId}. Account checked/created and PK registered on-chain.`,
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