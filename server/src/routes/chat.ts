import { Router } from 'express';
import * as ctrl from '../controllers/chatController.js';

const router = Router();

router.post('/', ctrl.chat);

export default router;
