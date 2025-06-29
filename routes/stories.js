const express = require('express');
const {
  createStory,
  getStories,
  getMyStories,
  viewStory,
  deleteStory
} = require('../controllers/storyController');
const { protect } = require('../middlewares/auth');
const { upload } = require('../config/cloudinary');

const router = express.Router();

router.use(protect);

router.post('/', upload.single('media'), createStory);
router.get('/', getStories);
router.get('/me', getMyStories);
router.put('/:storyId/view', viewStory);
router.delete('/:storyId', deleteStory);

module.exports = router;