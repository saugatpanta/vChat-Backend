const express = require('express');
const router = express.Router();
const storyController = require('../controllers/storyController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.post('/', protect, upload.single('media'), storyController.createStory);
router.get('/', protect, storyController.getStories);
router.get('/me', protect, storyController.getMyStories);
router.get('/:storyId', protect, storyController.getStory);
router.delete('/:storyId', protect, storyController.deleteStory);

module.exports = router;