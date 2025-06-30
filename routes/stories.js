const express = require('express');
const {
  createStory,
  getStories,
  getMyStories,
  getStory,
  deleteStory,
  getStoryViewers
} = require('../controllers/storyController');
const { protect } = require('../middlewares/auth');
const { upload } = require('../config/cloudinary');

const router = express.Router();

router.use(protect);

router.post('/', upload.single('media'), createStory);
router.get('/', getStories);
router.get('/me', getMyStories);
router.get('/:id', getStory);
router.delete('/:id', deleteStory);
router.get('/:id/viewers', getStoryViewers);

module.exports = router;