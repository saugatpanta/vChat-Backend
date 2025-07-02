const express = require('express');
const router = express.Router();
const {
  getUser,
  updateUser,
  followUser,
  unfollowUser,
  searchUsers,
  getSuggestions
} = require('../controllers/userController');
const { protect } = require('../middlewares/auth');

router.get('/:id', getUser);
router.get('/search/:query', searchUsers);
router.get('/suggestions', protect, getSuggestions);

router.use(protect);

router.put('/:id', updateUser);
router.post('/:id/follow', followUser);
router.post('/:id/unfollow', unfollowUser);

module.exports = router;