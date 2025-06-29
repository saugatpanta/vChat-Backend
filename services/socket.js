module.exports = function(io) {
  io.on('connection', socket => {
    console.log('New client connected:', socket.id);

    // Join user's own room for private messages
    socket.on('joinUser', userId => {
      socket.join(userId);
      console.log(`User ${userId} joined their room`);
    });

    // Join conversation room
    socket.on('joinConversation', conversationId => {
      socket.join(conversationId);
      console.log(`User joined conversation ${conversationId}`);
    });

    // Send and receive messages
    socket.on('sendMessage', message => {
      const conversation = message.conversation;
      const recipient = message.recipient;

      // Emit to conversation room
      io.to(conversation).emit('receiveMessage', message);

      // Emit to recipient's private room for notifications
      if (recipient) {
        io.to(recipient).emit('newMessageNotification', message);
      }
    });

    // Typing indicator
    socket.on('typing', data => {
      socket.to(data.conversation).emit('typing', data);
    });

    // Online status
    socket.on('userOnline', userId => {
      io.emit('userOnline', userId);
    });

    // Story notifications
    socket.on('newStory', story => {
      // Notify followers
      story.user.followers.forEach(followerId => {
        io.to(followerId).emit('newStoryNotification', story);
      });
    });

    // Disconnect
    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });
  });
};