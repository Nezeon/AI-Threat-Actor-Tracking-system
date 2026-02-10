import { Router } from 'express';
import * as ctrl from '../controllers/newsController.js';

const router = Router();

router.get('/', ctrl.getNews);

export default router;
