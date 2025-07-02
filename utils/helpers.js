const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;

// Generate token
const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};

// Generate random string
const generateRandomString = (length) => {
  return crypto.randomBytes(length).toString('hex');
};

// Filter object
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Upload file to Cloudinary
const uploadFile = async (file, folder) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload(
      file,
      { folder: `vchat/${folder}` },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
  });
};

// Delete file from Cloudinary
const deleteFile = async (publicId) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.destroy(publicId, (error, result) => {
      if (error) return reject(error);
      resolve(result);
    });
  });
};

module.exports = {
  createToken,
  generateRandomString,
  filterObj,
  uploadFile,
  deleteFile
};