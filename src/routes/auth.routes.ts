import { Router } from 'express';
import { refreshToken, register, login, logout } from '../controllers/auth.controller';

const router = Router();

// Define routes for registration and login
router.post('/refresh-token', refreshToken);
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);

export default router;