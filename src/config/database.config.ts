import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  const mongoUrl = process.env.MONGO_URL;

  if (!mongoUrl) {
    console.error('MONGO_URL is missing in .env');
    process.exit(1); // Stop app if missing
  }

  return {
    mongoUrl,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    },
  };
});
