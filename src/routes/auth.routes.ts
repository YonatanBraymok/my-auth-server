import { Router } from 'express';
import { refreshToken, register, login, logout, verifyEmail, requestPasswordReset, resetPassword, getProfile, updateProfile, changePassword } from '../controllers/auth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

// Define routes for registration and login
router.post('/refresh-token', refreshToken);
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/verify', verifyEmail);
router.post('/forgot-password', requestPasswordReset);
router.post('/reset-password', resetPassword);

// These routes demand an authentication token.
router.get('/me', authenticateToken, getProfile);
router.put('/profile', authenticateToken, updateProfile);
router.post('/change-password', authenticateToken, changePassword);

export default router;