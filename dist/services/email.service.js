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
exports.sendPasswordResetEmail = exports.sendVerificationEmail = void 0;
const resend_1 = require("resend");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config;
const resend = new resend_1.Resend(process.env.RESEND_API_KEY);
const fromEmail = process.env.FROM_EMAIL || 'onboarding@resend.dev';
const sendVerificationEmail = (toEmail, verificationToken) => __awaiter(void 0, void 0, void 0, function* () {
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const link = `${clientUrl}/verify?token=${verificationToken}`;
    try {
        const { data, error } = yield resend.emails.send({
            from: fromEmail,
            to: toEmail,
            subject: 'Verify your email',
            html: `
        <h3>Welcome!</h3>
        <p>Please click the link below to verify your email address:</p>
        <a href="${link}">Verify Email</a>
      `
        });
        if (error) {
            console.error("Resend error: ", error);
            return;
        }
    }
    catch (err) {
        console.error("Unexpected Error:", err);
    }
});
exports.sendVerificationEmail = sendVerificationEmail;
const sendPasswordResetEmail = (toEmail, resetToken) => __awaiter(void 0, void 0, void 0, function* () {
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const link = `${clientUrl}/reset-password?token=${resetToken}`;
    try {
        const { data, error } = yield resend.emails.send({
            from: fromEmail,
            to: toEmail,
            subject: 'Password Reset Request',
            html: `
        <h3>Password Reset</h3>
        <p>Click the link below to set a new password:</p>
        <a href="${link}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
      `
        });
        if (error) {
            console.error("Resend error: ", error);
            return;
        }
        console.log("Reset email sent successfully. ID:", data === null || data === void 0 ? void 0 : data.id);
    }
    catch (err) {
        console.error("Unexpected error:", err);
    }
});
exports.sendPasswordResetEmail = sendPasswordResetEmail;
