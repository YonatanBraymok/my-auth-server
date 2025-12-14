import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
    username: string;
    firstName: string;
    lastName: string;
    password: string;
    refreshTokens: string[];
}

const UserSchema: Schema = new Schema({
    username: { type: String, required: true, unique: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    password: { type: String, required: true },
    refreshTokens: { type: [String], default: [] },
});

export default mongoose.model<IUser>('User', UserSchema);