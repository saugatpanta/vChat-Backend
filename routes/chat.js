const express = require('express');
const {
  getConversations,
  getOrCreateConversation,
  getMessages,
  sendMessage,
  createGroupConversation,
  updateGroupConversation,
  deleteMessage,
  startVideoCall,
  endVideoCall
} = require('../controllers/chatController');
const { protect } = require('../middlewares/auth');

const router = express.Router();

router.use(protect);

router.get('/conversations', getConversations);
router.get('/conversations/:userId', getOrCreateConversation);
router.get('/conversations/:conversationId/messages', getMessages);
router.post('/conversations/:conversationId/messages', sendMessage);
router.post('/conversations/group', createGroupConversation);
router.put('/conversations/group/:conversationId', updateGroupConversation);
router.delete('/messages/:messageId', deleteMessage);
router.post('/conversations/:conversationId/call', startVideoCall);
router.post('/conversations/:conversationId/call/end', endVideoCall);

module.exports = router;