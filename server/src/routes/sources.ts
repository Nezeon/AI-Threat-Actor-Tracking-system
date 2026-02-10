import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import * as ctrl from '../controllers/sourceController.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const upload = multer({
  dest: path.resolve(__dirname, '../../uploads/'),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['.pdf', '.csv', '.xlsx', '.xls'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

const router = Router();

router.get('/:actorName', ctrl.getSourcesForActor);
router.post('/urls', ctrl.addUrl);
router.delete('/urls/:id', ctrl.removeUrl);
router.post('/files', upload.single('file'), ctrl.uploadFile);
router.delete('/files/:id', ctrl.removeFile);

export default router;
