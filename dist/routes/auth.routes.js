"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_controller_1 = require("../controllers/auth.controller");
const auth_middleware_1 = require("../middleware/auth.middleware");
const router = (0, express_1.Router)();
// Define routes for registration and login
router.post('/refresh-token', auth_controller_1.refreshToken);
router.post('/register', auth_controller_1.register);
router.post('/login', auth_controller_1.login);
router.post('/logout', auth_controller_1.logout);
router.post('/verify', auth_controller_1.verifyEmail);
router.post('/forgot-password', auth_controller_1.requestPasswordReset);
router.post('/reset-password', auth_controller_1.resetPassword);
// These routes demand an authentication token.
router.get('/me', auth_middleware_1.authenticateToken, auth_controller_1.getProfile);
router.put('/profile', auth_middleware_1.authenticateToken, auth_controller_1.updateProfile);
router.post('/change-password', auth_middleware_1.authenticateToken, auth_controller_1.changePassword);
router.delete('/profile', auth_middleware_1.authenticateToken, auth_controller_1.deleteAccount);
exports.default = router;
