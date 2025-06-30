const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.get('/', protect, userController.getUsers);
router.get('/:userId', protect, userController.getUserProfile);
router.put(
  '/profile-picture',
  protect,
  upload.single('profilePicture'),
  userController.updateProfilePicture
);
router.put(
  '/cover-photo',
  protect,
  upload.single('coverPhoto'),
  userController.updateCoverPhoto
);
router.put('/:userId/follow', protect, userController.followUser);
router.get('/:userId/followers', protect, userController.getFollowers);
router.get('/:userId/following', protect, userController.getFollowing);

module.exports = router;