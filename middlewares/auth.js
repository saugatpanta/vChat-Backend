const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', protect, authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.put('/reset-password/:resetToken', authController.resetPassword);
router.get('/profile', protect, authController.getProfile);
router.put(
  '/profile',
  protect,
  upload.single('profilePicture'),
  authController.updateProfile
);

module.exports = router;