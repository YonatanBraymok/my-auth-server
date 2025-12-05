import { Router } from 'express';
import { register, login } from '../controllers/auth.controller';

const router = Router();

// Define routes for registration and login
router.post('/register', register);
router.post('/login', login);

export default router;