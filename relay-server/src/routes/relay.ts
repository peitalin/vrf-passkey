import { Router, Request, Response } from 'express';
import { delegateService, DelegateActionRequest } from '../services/delegateService';

const router = Router();

// Middleware to parse binary data for signed delegates
const parseBinaryMiddleware = (req: Request, res: Response, next: any) => {
  if (req.headers['content-type'] === 'application/octet-stream') {
    let data: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      data.push(chunk);
    });
    req.on('end', () => {
      req.body = new Uint8Array(Buffer.concat(data));
      next();
    });
  } else {
    next();
  }
};

/**
 * POST /relay/create-account
 * Create account via delegate action
 * Accepts binary-encoded signed delegate actions for account creation
 */
router.post('/relay/create-account', parseBinaryMiddleware, async (req: Request, res: Response) => {
  console.log(`\nRELAY ENDPOINT HIT! /relay/create-account called`);
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`Request URL: ${req.url}`);
  console.log(`Query params:`, req.query);

  try {
    console.log(`📝 Request headers:`, req.headers);
    console.log(`📦 Request body type:`, typeof req.body);
    console.log(`📦 Request body instanceof Uint8Array:`, req.body instanceof Uint8Array);

    // Validate request body
    if (!req.body || !(req.body instanceof Uint8Array)) {
      console.log(`❌ Invalid request body validation failed`);
      return res.status(400).json({
        success: false,
        error: 'Invalid request body. Expected binary encoded signed delegate.'
      });
    }

    console.log(`📨 Received account creation delegate request (${req.body.length} bytes)`);

    // Get the new account ID from query parameter
    const newAccountId = req.query.newAccountId as string;
    if (!newAccountId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required query parameter: newAccountId'
      });
    }

    console.log(`🎯 Target account for creation: ${newAccountId}`);

    // Process the delegate action
    const request: DelegateActionRequest = {
      encodedSignedDelegate: req.body,
      description: 'account creation delegate action',
      newAccountId: newAccountId
    };

    const result = await delegateService.processDelegateAction(request);

    // Return the result directly - avoid JSON serialization of complex objects
    if (result.success) {
      console.log(`✅ Account creation successful: ${result.transactionHash}`);
      res.json({
        success: result.success,
        transactionHash: result.transactionHash,
        receiverId: result.receiverId,
        senderId: result.senderId,
        message: 'Account created successfully via delegate action'
      });
    } else {
      console.error(`❌ Account creation failed: ${result.error}`);
      res.status(500).json({
        success: result.success,
        error: result.error,
        message: 'Failed to create account via delegate action'
      });
    }

  } catch (error: any) {
    console.error('Account creation relay endpoint error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error creating account via delegate action'
    });
  }
});

export default router;