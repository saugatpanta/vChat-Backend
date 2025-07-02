module.exports = function(io) {
  io.on('connection', socket => {
    console.log(`User connected: ${socket.id}`);

    // Join user's room
    socket.on('join', userId => {
      socket.join(userId);
      console.log(`User ${userId} joined their room`);
    });

    // Join conversation room
    socket.on('joinConversation', conversationId => {
      socket.join(conversationId);
      console.log(`User joined conversation ${conversationId}`);
    });

    // Leave conversation room
    socket.on('leaveConversation', conversationId => {
      socket.leave(conversationId);
      console.log(`User left conversation ${conversationId}`);
    });

    // Send and receive messages
    socket.on('sendMessage', message => {
      io.to(message.conversation).emit('receiveMessage', message);
    });

    // Typing indicator
    socket.on('typing', data => {
      socket.to(data.conversationId).emit('typing', data.userId);
    });

    // Stop typing indicator
    socket.on('stopTyping', data => {
      socket.to(data.conversationId).emit('stopTyping', data.userId);
    });

    // Call handling
    socket.on('callUser', data => {
      io.to(data.recipientId).emit('callReceived', {
        signal: data.signal,
        callerId: data.callerId,
        isVideo: data.isVideo,
        conversationId: data.conversationId
      });
    });

    socket.on('answerCall', data => {
      io.to(data.callerId).emit('callAnswered', {
        signal: data.signal,
        conversationId: data.conversationId
      });
    });

    socket.on('endCall', data => {
      io.to(data.recipientId).emit('callEnded', {
        conversationId: data.conversationId
      });
    });

    // Disconnect
    socket.on('disconnect', () => {
      console.log(`User disconnected: ${socket.id}`);
    });
  });
};