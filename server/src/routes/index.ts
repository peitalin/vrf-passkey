import { Router } from 'express';

import healthRoutes from './health';
import registrationRoutes from './registration';
import authenticationRoutes from './authentication';
import accountRoutes from './account';

const router = Router();

// Mount all routes
router.use('/', healthRoutes);
router.use('/', registrationRoutes);
router.use('/', authenticationRoutes);
router.use('/', accountRoutes);

export default router;