const multer = require('multer');
const path = require('path');
const logger = require('../middlewares/logger');

// Configure storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './tmp/');
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png|gif|mp4|mov|avi|mp3|wav/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase();
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Error: Only image, video and audio files are allowed'));
  }
};

// Initialize Multer
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: fileFilter
});

module.exports = upload;
