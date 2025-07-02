const multer = require('multer');
const { cloudinary } = require('../config/cloudinary');
const { promisify } = require('util');
const fs = require('fs');
const unlinkAsync = promisify(fs.unlink);

const uploadToCloudinary = async (file, options = {}) => {
  try {
    const result = await cloudinary.uploader.upload(file.path, options);
    await unlinkAsync(file.path); // Delete file from server after upload
    return result;
  } catch (error) {
    await unlinkAsync(file.path); // Ensure file is deleted even if upload fails
    throw error;
  }
};

module.exports = {
  uploadToCloudinary
};