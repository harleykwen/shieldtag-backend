import mongoose, { Document, Schema } from 'mongoose';

export interface IRegistration extends Document {
  email: string;
  password: string;
  otp_id: string;
}

const RegistrationSchema: Schema = new Schema({
  email: { type: String, required: true, unique: false },
  password: { type: String, required: true },
  otp_id: { type: String, required: true },
});

export default mongoose.model<IRegistration>('Registration', RegistrationSchema);
