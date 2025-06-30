const express = require('express');
const {
  getUsers,
  getUser,
  updateUser,
  updateAvatar,
  followUser,
  unfollowUser,
  getFollowers,
  getFollowing
} = require('../controllers/userController');
const { protect } = require('../middlewares/auth');
const { upload } = require('../config/cloudinary');

const router = express.Router();

router.use(protect);

router.get('/', getUsers);
router.get('/:id', getUser);
router.put('/:id', updateUser);
router.put('/:id/avatar', upload.single('avatar'), updateAvatar);
router.put('/:id/follow', followUser);
router.put('/:id/unfollow', unfollowUser);
router.get('/:id/followers', getFollowers);
router.get('/:id/following', getFollowing);

module.exports = router;