const cloudinary = require('cloudinary').v2;
const logger = require('../middlewares/logger');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadToCloudinary = async (file, folder = 'vchat') => {
  try {
    const result = await cloudinary.uploader.upload(file, {
      folder,
      resource_type: 'auto',
    });
    return {
      url: result.secure_url,
      public_id: result.public_id,
    };
  } catch (error) {
    logger.error('Cloudinary upload error:', error);
    throw new Error('File upload failed');
  }
};

const deleteFromCloudinary = async (publicId) => {
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (error) {
    logger.error('Cloudinary delete error:', error);
    throw new Error('File deletion failed');
  }
};

module.exports = { uploadToCloudinary, deleteFromCloudinary };