import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
    email: string;
    firstName: string;
    lastName: string;
    password: string;
    refreshTokens: string[];
    country: string;
    city: string;
    isVerified: boolean;
    verificationToken: string;
}

const UserSchema: Schema = new Schema({
    email: { type: String, required: true, unique: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    password: { type: String, required: true },
    refreshTokens: { type: [String], default: [] },
    country: { type: String, required: true },
    city: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
});

export default mongoose.model<IUser>('User', UserSchema);