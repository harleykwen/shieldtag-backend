import express from 'express';
import dotenv from 'dotenv';
import authRoute from './routes/auth.route'

dotenv.config();

const app = express();

app.use(express.json());
app.use('/api/auth', authRoute);

export default app