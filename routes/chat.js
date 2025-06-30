const express = require('express');
const router = express.Router();
const chatController = require('../controllers/chatController');
const { protect } = require('../middlewares/auth');
const upload = require('../services/fileUpload');

router.get('/conversations', protect, chatController.getConversations);
router.post('/conversations', protect, chatController.createConversation);
router.post(
  '/conversations/group',
  protect,
  chatController.createGroupConversation
);
router.get(
  '/conversations/:conversationId/messages',
  protect,
  chatController.getMessages
);
router.post(
  '/conversations/:conversationId/messages',
  protect,
  upload.array('media', 10),
  chatController.sendMessage
);
router.delete(
  '/messages/:messageId',
  protect,
  chatController.deleteMessage
);
router.post('/call', protect, chatController.startCall);
router.put('/call/:messageId', protect, chatController.endCall);

module.exports = router;