import { Router } from 'express';
import * as ctrl from '../controllers/actorController.js';

const router = Router();

router.get('/', ctrl.getAllActors);
router.get('/:id', ctrl.getActor);
router.post('/generate', ctrl.generateActor);
router.post('/:id/refresh-section', ctrl.refreshSection);
router.put('/:id', ctrl.updateActorHandler);
router.delete('/:id', ctrl.deleteActorHandler);

export default router;
