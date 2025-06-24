import { Router } from 'express';

import healthRoutes from './health';
import relayRoutes from './relay';

const router = Router();

// Mount all routes
router.use('/', healthRoutes);
router.use('/', relayRoutes);

export default router;