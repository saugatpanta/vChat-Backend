const express = require('express');
const router = express.Router();
const {
  createStory,
  getStories,
  getStory,
  deleteStory,
  viewStory,
  reactToStory,
} = require('../controllers/storyController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.route('/')
  .post(protect, upload.single('file'), createStory)
  .get(protect, getStories);

router.route('/:id')
  .get(protect, getStory)
  .delete(protect, deleteStory);

router.post('/:id/view', protect, viewStory);
router.post('/:id/react', protect, reactToStory);

module.exports = router;