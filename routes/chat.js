const express = require('express');
const {
  getOrCreateConversation,
  getConversations,
  getMessages,
  sendMessage,
  deleteMessage,
  createGroup,
  updateGroup
} = require('../controllers/chatController');
const { protect } = require('../middlewares/auth');
const { upload } = require('../config/cloudinary');

const router = express.Router();

router.use(protect);

router.post('/conversations', getOrCreateConversation);
router.get('/conversations', getConversations);
router.get('/messages/:conversationId', getMessages);
router.post('/messages', upload.array('media', 10), sendMessage);
router.delete('/messages/:messageId', deleteMessage);
router.post('/groups', createGroup);
router.put('/groups/:groupId', updateGroup);

module.exports = router;