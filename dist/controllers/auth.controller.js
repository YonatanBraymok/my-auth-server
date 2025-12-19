"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteAccount = exports.changePassword = exports.updateProfile = exports.getProfile = exports.resetPassword = exports.requestPasswordReset = exports.verifyEmail = exports.logout = exports.login = exports.register = exports.refreshToken = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const user_model_1 = __importDefault(require("../models/user.model"));
const crypto_1 = __importDefault(require("crypto"));
const email_service_1 = require("../services/email.service");
const generateRefreshToken = (userId) => {
    return jsonwebtoken_1.default.sign({ userId }, process.env.REFRESH_TOKEN_SECRET || 'refresh_default_secret', { expiresIn: '7d' });
};
const refreshToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ message: 'Refresh token is required' });
    }
    const refreshSecret = process.env.REFRESH_TOKEN_SECRET || 'refresh_default_secret';
    jsonwebtoken_1.default.verify(token, refreshSecret, (err, userPayload) => __awaiter(void 0, void 0, void 0, function* () {
        if (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }
        try {
            const user = yield user_model_1.default.findById(userPayload.userId);
            if (!user || !user.refreshTokens || !user.refreshTokens.includes(token)) {
                return res.status(403).json({ message: 'Refresh token not recognized' });
            }
            const accessSecret = process.env.JWT_SECRET || 'default_secret';
            const newAccessToken = jsonwebtoken_1.default.sign({ userId: user._id, email: user.email }, accessSecret, { expiresIn: '15m' });
            res.json({ accessToken: newAccessToken });
        }
        catch (error) {
            res.status(500).json({ message: 'Internal server error', error });
        }
    }));
});
exports.refreshToken = refreshToken;
// Password validation function
const validatePassword = (password) => {
    if (password.length < 8)
        return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(password))
        return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(password))
        return "Password must contain at least one lowercase letter";
    if (!/[0-9]/.test(password))
        return "Password must contain at least one digit";
    if (!/[!@#$%^&*]/.test(password))
        return "Password must contain at least one special character (!@#$%^&*)";
    return null;
};
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password, firstName, lastName, country, city } = req.body; // Destructure username and password from request body
        if (!email || !password || !firstName || !lastName || !country || !city) {
            res.status(400).json({ message: 'All fields are required!' });
            return;
        }
        const passwordError = validatePassword(password);
        if (passwordError) {
            res.status(400).json({ message: passwordError });
            return;
        }
        const existingUser = yield user_model_1.default.findOne({ email });
        if (existingUser) {
            res.status(409).json({ message: 'User already exists' });
            return;
        }
        const hashedPassword = yield bcrypt_1.default.hash(password, 10);
        const verificationToken = crypto_1.default.randomBytes(32).toString('hex'); // For Email Verification.
        const newUser = yield user_model_1.default.create({
            email,
            firstName,
            lastName,
            country,
            city,
            password: hashedPassword,
            verificationToken,
            isVerified: false
        });
        try {
            yield (0, email_service_1.sendVerificationEmail)(email, verificationToken);
        }
        catch (error) {
            console.error("Email send failed:", error);
        }
        res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.', userId: newUser._id });
    }
    catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error', error });
    }
});
exports.register = register;
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const secret = process.env.JWT_SECRET || 'default_secret';
        const { email, password } = req.body;
        const user = yield user_model_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({ message: 'User not found' });
            return;
        }
        const passwordMatch = yield bcrypt_1.default.compare(password, user.password);
        if (!passwordMatch) {
            res.status(401).json({ message: 'Wrong password' });
            return;
        }
        if (!user.isVerified) {
            res.status(403).json({ message: 'You must verify your email first!.' });
            return;
        }
        const accessToken = jsonwebtoken_1.default.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || 'default_secret', { expiresIn: '15m' });
        const refreshToken = generateRefreshToken(user._id);
        if (!user.refreshTokens) {
            user.refreshTokens = [];
        }
        user.refreshTokens.push(refreshToken);
        yield user.save();
        res.json({ message: 'Login successful', accessToken, refreshToken });
    }
    catch (error) {
        res.status(500).json({ message: 'Internal server error', error });
    }
});
exports.login = login;
const logout = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }
    try {
        yield user_model_1.default.findOneAndUpdate({ refreshTokens: token }, { $pull: { refreshTokens: token } });
        res.json({ message: 'Logouted successfully' });
    }
    catch (error) {
        res.status(500).json({ message: 'Internal server error', error });
    }
});
exports.logout = logout;
const verifyEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { token } = req.body;
    if (!token) {
        res.status(400).json({ message: 'Token is required' });
        return;
    }
    try {
        const user = yield user_model_1.default.findOne({ verificationToken: token });
        if (!user) {
            res.status(400).json({ message: 'Invalid or expired token' });
            return;
        }
        user.isVerified = true;
        user.verificationToken = undefined;
        yield user.save();
        res.status(200).json({ message: 'Email verified successfully!' });
    }
    catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});
exports.verifyEmail = verifyEmail;
const requestPasswordReset = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email } = req.body;
    try {
        const user = yield user_model_1.default.findOne({ email });
        if (!user) {
            // Apparently Gemini says this is a security trick to prevent account breach...
            // Meaning we say we sent an email to a non-existent account, even though we didnt.
            res.status(200).json({ message: 'Password reset request sent to this email!.' });
            return;
        }
        const resetToken = crypto_1.default.randomBytes(32).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour.
        yield user.save();
        yield (0, email_service_1.sendPasswordResetEmail)(user.email, resetToken);
        res.status(200).json({ message: 'Password reset request sent to this email!.' });
    }
    catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});
exports.requestPasswordReset = requestPasswordReset;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { token, newPassword } = req.body;
    try {
        const user = yield user_model_1.default.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        if (!user) {
            res.status(400).json({ message: 'Invalid or expired token' });
            return;
        }
        const passwordError = validatePassword(newPassword);
        if (passwordError) {
            res.status(400).json({ message: passwordError });
            return;
        }
        const isSamePassword = yield bcrypt_1.default.compare(newPassword, user.password);
        if (isSamePassword) {
            res.status(400).json({ message: 'New password cannot be the same as the old password' });
            return;
        }
        const hashedPassword = yield bcrypt_1.default.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        yield user.save();
        res.status(200).json({ message: 'Password has been reset successfully!' });
    }
    catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});
exports.resetPassword = resetPassword;
const getProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const userId = req.user.userId; // userId comes from middleware.
        const user = yield user_model_1.default.findById(userId).select('-password -refreshToken -verificationToken -resetPasswordToken');
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        res.status(200).json(user);
    }
    catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});
exports.getProfile = getProfile;
const updateProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { firstName, lastName, country, city } = req.body;
        const updatedUser = yield user_model_1.default.findByIdAndUpdate(userId, { firstName, lastName, country, city }, { new: true, runValidators: true }).select('-password');
        res.status(200).json(updatedUser);
    }
    catch (error) {
        console.error("UpdateProfile Error:", error);
        res.status(500).json({ message: 'Server error', error });
    }
});
exports.updateProfile = updateProfile;
const changePassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            res.status(400).json({ message: 'All fields are required' });
            return;
        }
        const user = yield user_model_1.default.findById(userId);
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        const isMatch = yield bcrypt_1.default.compare(currentPassword, user.password);
        if (!isMatch) {
            res.status(400).json({ message: 'Incorrect current password' });
            return;
        }
        const passwordError = validatePassword(newPassword);
        if (passwordError) {
            res.status(400).json({ message: passwordError });
            return;
        }
        const isSame = yield bcrypt_1.default.compare(newPassword, user.password);
        if (isSame) {
            res.status(400).json({ message: 'New password cannot be the same as old password' });
            return;
        }
        const hashedPassword = yield bcrypt_1.default.hash(newPassword, 10);
        user.password = hashedPassword;
        yield user.save();
        res.status(200).json({ message: 'Password changed successfully' });
    }
    catch (error) {
        console.error("ChangePassword Error:", error);
        res.status(500).json({ message: 'Server error' });
    }
});
exports.changePassword = changePassword;
const deleteAccount = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        if (!userId) {
            res.status(400).json({ message: 'User ID missing' });
            return;
        }
        yield user_model_1.default.findByIdAndDelete(userId);
        res.status(200).json({ message: 'Account deleted successfully' });
    }
    catch (error) {
        console.error("DeleteAccount Error: ", error);
        res.status(500).json({ message: 'Server error' });
    }
});
exports.deleteAccount = deleteAccount;
