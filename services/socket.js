const Call = require('../models/Call');
const Notification = require('../models/Notification');
const WebRTCService = require('./webrtcService');

module.exports = function(io, redisClient) {
  io.on('connection', (socket) => {
    console.log(`New connection: ${socket.id}`);
    
    // Join user's room
    socket.on('joinUser', (userId) => {
      socket.join(userId);
      console.log(`User ${userId} joined their room`);
    });

    // Chat functionality
    socket.on('sendMessage', async (message) => {
      try {
        const { conversationId, sender, text } = message;
        socket.to(conversationId).emit('receiveMessage', message);
      } catch (err) {
        console.error('Error sending message:', err);
      }
    });

    // Call functionality
    socket.on('initiateCall', async ({ caller, recipient, type }) => {
      try {
        const roomId = await WebRTCService.createRoom(caller, type);
        socket.to(recipient).emit('incomingCall', { caller, roomId, type });
        socket.emit('callInitiated', { roomId });
      } catch (err) {
        console.error('Error initiating call:', err);
      }
    });

    socket.on('answerCall', async ({ roomId, answerer }) => {
      try {
        const roomInfo = await WebRTCService.getRoomInfo(roomId);
        socket.to(roomInfo.host).emit('callAnswered', { answerer, roomId });
        await WebRTCService.joinRoom(roomId, answerer);
      } catch (err) {
        console.error('Error answering call:', err);
      }
    });

    socket.on('endCall', async ({ roomId, userId }) => {
      try {
        const roomInfo = await WebRTCService.getRoomInfo(roomId);
        socket.to(roomId).emit('callEnded', { endedBy: userId });
        await WebRTCService.leaveRoom(roomId, userId);
      } catch (err) {
        console.error('Error ending call:', err);
      }
    });

    // WebRTC signaling
    socket.on('webrtc-signaling', ({ roomId, signal, sender }) => {
      socket.to(roomId).emit('webrtc-signaling', { signal, sender });
    });

    // Disconnect
    socket.on('disconnect', () => {
      console.log(`User disconnected: ${socket.id}`);
    });
  });
};