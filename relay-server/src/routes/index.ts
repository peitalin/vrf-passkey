import { Router } from 'express';

import healthRoutes from './health';
import accountsRoutes from './accounts';

const router = Router();

// Mount all routes
router.use('/', healthRoutes);
router.use('/', accountsRoutes);

export default router;