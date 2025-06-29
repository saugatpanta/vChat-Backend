const express = require('express');
const router = express.Router();
const { protect } = require('../middlewares/auth');
const {
  getUsers,
  getUser,
  updateProfile,
  followUser,
  unfollowUser,
  getFollowers,
  getFollowing,
  deleteAccount
} = require('../controllers/userController');
const upload = require('../services/fileUpload');

router.get('/', protect, getUsers);
router.get('/:id', protect, getUser);
router.put('/profile', protect, upload.single('profilePhoto'), updateProfile);
router.put('/follow/:id', protect, followUser);
router.put('/unfollow/:id', protect, unfollowUser);
router.get('/followers/:id', protect, getFollowers);
router.get('/following/:id', protect, getFollowing);
router.delete('/', protect, deleteAccount);

module.exports = router;
