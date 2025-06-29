module.exports = {
  JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
  JWT_EXPIRE: process.env.JWT_EXPIRE || '30d',
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/vchat',
  EMAIL_HOST: process.env.EMAIL_HOST || 'smtp.mailtrap.io',
  EMAIL_PORT: process.env.EMAIL_PORT || 2525,
  EMAIL_USER: process.env.EMAIL_USER || 'your_email_user',
  EMAIL_PASS: process.env.EMAIL_PASS || 'your_email_pass',
  CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME || 'your_cloud_name',
  CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY || 'your_api_key',
  CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET || 'your_api_secret',
  NODE_ENV: process.env.NODE_ENV || 'development',
};