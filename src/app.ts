import connectDB from './config/db.config';
import app from './index';

const port = process.env.PORT || 3000;

connectDB();

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
