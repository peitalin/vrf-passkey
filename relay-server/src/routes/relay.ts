import { Router, Request, Response } from 'express';
import { nearAccountService } from '../accountService';
import type { RegistrationSSEEvent } from '../types';

const router = Router();

interface RequestParams {
  accountId: string;
  publicKey: string;
  initialBalance: string;
}

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
router.post('/relay/create-account', async (req: Request<any, any, RequestParams>, res: Response) => {
  try {
    console.log('POST /relay/create-account', req.body);
    const { accountId, publicKey } = validateCreateAccountParams(req.body);

    const result = await nearAccountService.createAccount({
      accountId,
      publicKey,
    });

    if (!result.success) throw new Error(result.error || 'Account creation failed');

    res.status(200).json(result);

  } catch (error: any) {
    console.error('Account creation failed:', error.message);
    res.status(500).json({
      success: false,
      error: error.message || 'Unknown server error'
    });
  }
});

const validateCreateAccountParams = (body: RequestParams) => {
  const { accountId, publicKey } = body;
  if (!accountId || typeof accountId !== 'string') throw new Error('Missing or invalid accountId');
  if (!publicKey || typeof publicKey !== 'string') throw new Error('Missing or invalid publicKey');
  return { accountId, publicKey };
}

/**
 * POST /relay/create-account-sse
 * Create a new account with Server-Sent Events for real-time progress updates
 *
 * Body: JSON with accountId, publicKey, and optional initialBalance
 * Response: Server-Sent Events stream with progress updates
 */
router.post('/relay/create-account-sse', async (req: Request<any, any, RequestParams>, res: Response) => {
  try {
    console.log('POST /relay/create-account-sse', req.body);

    const { accountId, publicKey } = validateCreateAccountParams(req.body);

    // Set up SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    });

    const sessionId = `sse_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    const emitSSEEvent = (event: RegistrationSSEEvent) => {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    };

    // Send initial connection event
    emitSSEEvent({
      step: 1,
      sessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'SSE connection established, starting account creation...'
    });

    // Create account with SSE event emission
    const result = await nearAccountService.createAccount(
      { accountId, publicKey },
      emitSSEEvent,
      sessionId
    );

    // Send final result
    res.write(`data: ${JSON.stringify({
      type: 'final-result',
      success: result.success,
      ...(result.success
        ? { transactionHash: result.transactionHash, accountId: result.accountId }
        : { error: result.error }
      ),
      message: result.message
    })}\n\n`);

    res.write('data: [DONE]\n\n');
    res.end();

  } catch (error: any) {
    console.error('SSE endpoint error:', error.message);

    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: error.message || 'Unknown server error'
      });
    } else {
      res.write(`data: ${JSON.stringify({
        type: 'error',
        error: error.message || 'Unknown server error'
      })}\n\n`);
      res.end();
    }
  }
});

export default router;