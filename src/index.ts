import express from 'express';
import authRoute from './routes/auth.route'
import profileRoute from './routes/profile.route'
import rateLimit from 'express-rate-limit'
import cors from 'cors'


const app = express();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10000,                 // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,    // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,     // Disable `X-RateLimit-*` headers
});

app.use(express.json());
app.use(cors());
app.use(limiter);
app.use('/api/auth', authRoute);
app.use('/api/profile', profileRoute);

export default app