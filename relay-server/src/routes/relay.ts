import { Router, Request, Response } from 'express';
import { nearAccountService } from '../accountService';
import type { RegistrationSSEEvent } from '../types';

const router = Router();

/**
 * POST /relay/create-account
 * Create a new account directly using relay server authority (simple JSON response)
 *
 * Body: JSON with accountId, publicKey, and optional initialBalance
 * {
 *   "accountId": "user.near",
 *   "publicKey": "ed25519:ABC123...",
 *   "initialBalance": "20000000000000000000000" // Optional, in yoctoNEAR (defaults to 0.02 NEAR)
 * }
 *
 * Returns: JSON response with success/error status
 * For real-time progress updates, use /relay/create-account-sse instead
 */
router.post('/relay/create-account', async (req: Request, res: Response) => {
  try {
    console.log('POST /relay/create-account');
    console.log('Request body:', req.body);

    const { accountId, publicKey, initialBalance } = req.body;

    if (!accountId || typeof accountId !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid accountId',
        message: 'accountId is required in request body'
      });
    }

    if (!publicKey || typeof publicKey !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid publicKey',
        message: 'publicKey is required in request body'
      });
    }

    // Optional validation for initialBalance
    if (initialBalance !== undefined && typeof initialBalance !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid initialBalance',
        message: 'initialBalance must be a string (in yoctoNEAR) if provided'
      });
    }

    const result = await nearAccountService.createAccount({
      accountId,
      publicKey,
      initialBalance
    });

    if (result.success) {
      res.status(200).json(result);
    } else {
      console.log(`Account creation failed: ${result.error}`);
      res.status(500).json(result);
    }

  } catch (error: any) {
    console.error('Account creation endpoint error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Unknown server error',
      message: 'Failed to create account'
    });
  }
});

/**
 * POST /relay/create-account-sse
 * Create a new account with Server-Sent Events for real-time progress updates
 *
 * Body: JSON with accountId, publicKey, and optional initialBalance
 * Response: Server-Sent Events stream with progress updates
 */
router.post('/relay/create-account-sse', async (req: Request, res: Response) => {
  try {
    console.log('POST /relay/create-account-sse');
    console.log('Request body:', req.body);

    const { accountId, publicKey, initialBalance } = req.body;

    // Validate request parameters
    if (!accountId || typeof accountId !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid accountId',
        message: 'accountId is required in request body'
      });
    }

    if (!publicKey || typeof publicKey !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid publicKey',
        message: 'publicKey is required in request body'
      });
    }

    if (initialBalance !== undefined && typeof initialBalance !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid initialBalance',
        message: 'initialBalance must be a string (in yoctoNEAR) if provided'
      });
    }

    // Set up SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    });

    // Generate session ID for this request
    const sessionId = `sse_${Date.now()}_${Math.random().toString(36).substring(2)}`;

    // SSE event emitter function
    const emitSSEEvent = (event: RegistrationSSEEvent) => {
      const eventData = JSON.stringify(event);
      res.write(`data: ${eventData}\n\n`);
    };

    // Send initial connection event
    emitSSEEvent({
      step: 1,
      sessionId: sessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'SSE connection established, starting account creation...'
    });

    try {
      // Create account with SSE event emission
      const result = await nearAccountService.createAccount(
        { accountId, publicKey, initialBalance },
        emitSSEEvent,
        sessionId
      );

      // Send final result
      if (result.success) {
        res.write(`data: ${JSON.stringify({
          type: 'final-result',
          success: true,
          transactionHash: result.transactionHash,
          accountId: result.accountId,
          message: result.message
        })}\n\n`);
      } else {
        res.write(`data: ${JSON.stringify({
          type: 'final-result',
          success: false,
          error: result.error,
          message: result.message
        })}\n\n`);
      }

    } catch (createError: any) {
      console.error('Account creation error during SSE:', createError);

      // Send error event
      emitSSEEvent({
        step: 0,
        sessionId: sessionId,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: `Account creation failed: ${createError.message}`,
        error: createError.message || 'Unknown account creation error'
      });

      // Send final error result
      res.write(`data: ${JSON.stringify({
        type: 'final-result',
        success: false,
        error: createError.message || 'Unknown server error',
        message: 'Failed to create account'
      })}\n\n`);
    }

    // Close the SSE connection
    res.write('data: [DONE]\n\n');
    res.end();

  } catch (error: any) {
    console.error('SSE endpoint error:', error);

    // If headers haven't been sent yet, send JSON error response
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: error.message || 'Unknown server error',
        message: 'Failed to create account'
      });
    } else {
      // If in SSE mode, send error and close
      res.write(`data: ${JSON.stringify({
        type: 'error',
        error: error.message || 'Unknown server error'
      })}\n\n`);
      res.end();
    }
  }
});

export default router;