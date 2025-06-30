const multer = require('multer');
const { storage } = require('../config/cloudinary');
const { StatusCodes } = require('http-status-codes');

const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'video/mp4',
      'video/quicktime',
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      const error = new Error('Invalid file type');
      error.statusCode = StatusCodes.BAD_REQUEST;
      return cb(error, false);
    }

    cb(null, true);
  },
});

module.exports = upload;