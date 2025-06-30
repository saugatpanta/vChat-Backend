const { socketAuth } = require('../middlewares/auth');
const Conversation = require('../models/Conversation');
const User = require('../models/User');

module.exports = (io) => {
  io.use(socketAuth).on('connection', (socket) => {
    console.log(`User connected: ${socket.user.username}`);

    // Join user's personal room
    socket.join(socket.user._id.toString());

    // Join all conversation rooms the user is part of
    Conversation.find({ participants: socket.user._id })
      .select('_id')
      .then((conversations) => {
        conversations.forEach((conversation) => {
          socket.join(conversation._id.toString());
        });
      });

    // Handle typing events
    socket.on('typing', (conversationId) => {
      socket.to(conversationId).emit('typing', {
        userId: socket.user._id,
        username: socket.user.username,
      });
    });

    // Handle stop typing events
    socket.on('stopTyping', (conversationId) => {
      socket.to(conversationId).emit('stopTyping', {
        userId: socket.user._id,
      });
    });

    // Handle call events
    socket.on('callAccepted', ({ conversationId, callerId }) => {
      io.to(callerId).emit('callAccepted', { conversationId });
    });

    socket.on('callDeclined', ({ conversationId, callerId }) => {
      io.to(callerId).emit('callDeclined', { conversationId });
    });

    // Handle online status
    socket.on('disconnect', async () => {
      console.log(`User disconnected: ${socket.user.username}`);

      // Update user's online status with a delay to account for reconnects
      setTimeout(async () => {
        const sockets = await io.in(socket.user._id.toString()).fetchSockets();
        if (sockets.length === 0) {
          const user = await User.findById(socket.user._id);
          if (user) {
            user.isOnline = false;
            user.lastSeen = new Date();
            await user.save();
            
            // Notify all conversations the user is part of
            Conversation.find({ participants: user._id })
              .select('_id')
              .then((conversations) => {
                conversations.forEach((conversation) => {
                  io.to(conversation._id.toString()).emit('userStatusChanged', {
                    userId: user._id,
                    isOnline: false,
                    lastSeen: user.lastSeen,
                  });
                });
              });
          }
        }
      }, 5000); // 5 seconds delay
    });
  });
};