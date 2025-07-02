const express = require('express');
const router = express.Router();
const {
  createStory,
  getStories,
  getStory,
  deleteStory,
  viewStory
} = require('../controllers/storyController');
const { protect } = require('../middlewares/auth');

router.use(protect);

router.post('/', createStory);
router.get('/', getStories);
router.get('/:id', getStory);
router.delete('/:id', deleteStory);
router.post('/:id/view', viewStory);

module.exports = router;