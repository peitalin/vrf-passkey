import { Router, Request, Response } from 'express';

const router = Router();

router.get('/', (req: Request, res: Response) => {
  const timestamp = new Date().toISOString();
  console.log(`Health check requested at ${timestamp}`);
  res.send(`Web3 Authn Relay Server is running! (${timestamp})`);
});

export default router;