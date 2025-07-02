const express = require('express');
const router = express.Router();
const {
  getConversations,
  getOrCreateConversation,
  getMessages,
  sendMessage,
  markAsRead,
  startVideoCall,
  updateCallStatus
} = require('../controllers/chatController');
const { protect } = require('../middlewares/auth');

router.use(protect);

router.get('/conversations', getConversations);
router.post('/conversations', getOrCreateConversation);
router.get('/messages/:conversationId', getMessages);
router.post('/messages', sendMessage);
router.put('/messages/read/:conversationId', markAsRead);
router.post('/call/start', startVideoCall);
router.put('/call/update/:messageId', updateCallStatus);

module.exports = router;