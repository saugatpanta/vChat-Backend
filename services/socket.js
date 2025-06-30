const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');

module.exports = (io) => {
  io.on('connection', (socket) => {
    console.log(`New socket connection: ${socket.id}`);

    // Join user's room
    socket.on('joinUser', (userId) => {
      socket.join(userId);
      console.log(`User ${userId} joined their room`);
    });

    // Join conversation room
    socket.on('joinConversation', (conversationId) => {
      socket.join(conversationId);
      console.log(`Socket ${socket.id} joined conversation ${conversationId}`);
    });

    // Leave conversation room
    socket.on('leaveConversation', (conversationId) => {
      socket.leave(conversationId);
      console.log(`Socket ${socket.id} left conversation ${conversationId}`);
    });

    // Typing indicator
    socket.on('typing', ({ conversationId, userId }) => {
      socket.broadcast.to(conversationId).emit('typing', userId);
    });

    // Stop typing indicator
    socket.on('stopTyping', (conversationId) => {
      socket.broadcast.to(conversationId).emit('stopTyping');
    });

    // Message read receipt
    socket.on('markAsRead', async ({ messageId, userId }) => {
      try {
        const message = await Message.findById(messageId);
        
        if (!message.readBy.includes(userId)) {
          message.readBy.push(userId);
          await message.save();
          
          io.to(message.conversation.toString()).emit('messageRead', {
            messageId,
            readBy: message.readBy
          });
        }
      } catch (err) {
        console.error(err);
      }
    });

    // Online status
    socket.on('online', (userId) => {
      socket.broadcast.emit('userOnline', userId);
    });

    // Offline status
    socket.on('offline', (userId) => {
      socket.broadcast.emit('userOffline', userId);
    });

    // Call handling
    socket.on('callAccepted', ({ callId, userId }) => {
      io.to(callId).emit('callAccepted', userId);
    });

    socket.on('callRejected', ({ callId, userId }) => {
      io.to(callId).emit('callRejected', userId);
    });

    socket.on('callIceCandidate', ({ callId, candidate }) => {
      socket.broadcast.to(callId).emit('callIceCandidate', candidate);
    });

    socket.on('callOffer', ({ callId, offer, to }) => {
      io.to(to).emit('callOffer', { callId, offer });
    });

    socket.on('callAnswer', ({ callId, answer }) => {
      socket.broadcast.to(callId).emit('callAnswer', answer);
    });

    // Disconnect
    socket.on('disconnect', () => {
      console.log(`Socket disconnected: ${socket.id}`);
    });
  });
};