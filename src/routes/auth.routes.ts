import { Router } from 'express';
import { refreshToken, register, login, logout, verifyEmail } from '../controllers/auth.controller';

const router = Router();

// Define routes for registration and login
router.post('/refresh-token', refreshToken);
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/verify', verifyEmail);

export default router;