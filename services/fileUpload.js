const multer = require('multer');
const path = require('path');
const logger = require('../middlewares/logger');

// Set up storage for uploaded files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './tmp/');
  },
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + '-' + Date.now() + path.extname(file.originalname)
    );
  },
});

// File filter to accept only certain file types
const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png|gif|mp4|mov|avi|mp3|wav|pdf|doc|docx/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Error: File upload only supports the following filetypes - ' + filetypes));
  }
};

// Initialize upload
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: fileFilter,
}).single('file');

// Middleware to handle file upload
const handleFileUpload = (req, res, next) => {
  upload(req, res, (err) => {
    if (err) {
      logger.error(`File upload error: ${err.message}`);
      return res.status(400).json({
        success: false,
        message: err.message,
      });
    }
    next();
  });
};

module.exports = handleFileUpload;