import mongoose, { Document, Schema } from 'mongoose';

export interface IOtp extends Document {
  email: string;
  code: string;
  type: 'register' | 'login';
  expiresAt: Date;
}

const OtpSchema: Schema = new Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  type: { type: String, enum: ['register', 'login'], required: true },
  expiresAt: { type: Date, required: true },
});

// Auto-remove expired OTPs
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IOtp>('Otp', OtpSchema);
