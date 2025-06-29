const express = require('express');
const router = express.Router();
const {
  getUsers,
  getUser,
  updateProfile,
  followUser,
  unfollowUser,
  getFollowers,
  getFollowing,
  deleteAccount,
} = require('../controllers/userController');
const { protect, authorize } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.get('/', protect, authorize('admin'), getUsers);
router.get('/:id', protect, getUser);
router.put('/profile', protect, upload.single('profilePhoto'), updateProfile);
router.put('/follow/:id', protect, followUser);
router.put('/unfollow/:id', protect, unfollowUser);
router.get('/followers/:id', protect, getFollowers);
router.get('/following/:id', protect, getFollowing);
router.delete('/', protect, deleteAccount);

module.exports = router;