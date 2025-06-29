const express = require('express');
const router = express.Router();
const {
  startConversation,
  getConversations,
  getConversation,
  sendMessage,
  getMessages,
  deleteMessage,
  searchUsers,
  updateStatus,
} = require('../controllers/chatController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.route('/conversations')
  .post(protect, startConversation)
  .get(protect, getConversations);

router.get('/conversations/:id', protect, getConversation);

router.route('/messages')
  .post(protect, upload.single('file'), sendMessage);

router.get('/messages/:conversationId', protect, getMessages);
router.delete('/messages/:id', protect, deleteMessage);

router.get('/search', protect, searchUsers);
router.put('/status', protect, updateStatus);

module.exports = router;