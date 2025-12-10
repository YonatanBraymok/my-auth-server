import { Router } from 'express';
import { refreshToken, register, login } from '../controllers/auth.controller';

const router = Router();

// Define routes for registration and login
router.post('/register', register);
router.post('/login', login);
router.post('/refresh-token', refreshToken);

export default router;