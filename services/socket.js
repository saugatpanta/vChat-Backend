const logger = require('../middlewares/logger');
const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');

const configureSocket = (io) => {
  io.on('connection', (socket) => {
    logger.info(`New socket connection: ${socket.id}`);

    // Join user's room
    socket.on('join', async (userId) => {
      try {
        socket.join(userId);
        logger.info(`User ${userId} joined socket room`);

        // Update user status to online
        await User.findByIdAndUpdate(userId, { status: 'online' });

        // Notify friends
        const user = await User.findById(userId).select('following');
        user.following.forEach(friendId => {
          io.to(friendId.toString()).emit('friendStatus', {
            userId,
            status: 'online',
          });
        });
      } catch (error) {
        logger.error(`Socket join error: ${error.message}`);
      }
    });

    // Handle new message
    socket.on('sendMessage', async (data) => {
      try {
        const { conversationId, senderId, content, type, media } = data;

        // Create message in DB
        const message = await Message.create({
          conversation: conversationId,
          sender: senderId,
          content,
          type,
          media,
        });

        // Update conversation's last message
        const conversation = await Conversation.findByIdAndUpdate(
          conversationId,
          {
            lastMessage: message._id,
            updatedAt: Date.now(),
          },
          { new: true }
        ).populate('participants', 'username profilePhoto status lastSeen');

        // Populate sender info
        const populatedMessage = await Message.findById(message._id).populate(
          'sender',
          'username profilePhoto'
        );

        // Emit to all participants
        conversation.participants.forEach((participant) => {
          io.to(participant._id.toString()).emit('newMessage', {
            conversationId,
            message: populatedMessage,
          });
        });
      } catch (error) {
        logger.error(`Socket sendMessage error: ${error.message}`);
      }
    });

    // Handle message read
    socket.on('markAsRead', async ({ messageId, userId, conversationId }) => {
      try {
        const message = await Message.findByIdAndUpdate(
          messageId,
          { $addToSet: { readBy: userId } },
          { new: true }
        );

        if (message) {
          io.to(conversationId).emit('messageRead', {
            messageId,
            readBy: message.readBy,
          });
        }
      } catch (error) {
        logger.error(`Socket markAsRead error: ${error.message}`);
      }
    });

    // Handle typing indicator
    socket.on('typing', ({ conversationId, userId, isTyping }) => {
      socket.to(conversationId).emit('typing', { userId, isTyping });
    });

    // Handle disconnect
    socket.on('disconnect', async () => {
      try {
        logger.info(`Socket disconnected: ${socket.id}`);

        // Find user by socket ID and update status
        // Note: In a real app, you'd need a way to map socket IDs to user IDs
        // This is a simplified version
        const userId = socket.userId; // You'd need to set this when the user joins
        if (userId) {
          await User.findByIdAndUpdate(userId, {
            status: 'offline',
            lastSeen: Date.now(),
          });

          // Notify friends
          const user = await User.findById(userId).select('following');
          user.following.forEach(friendId => {
            io.to(friendId.toString()).emit('friendStatus', {
              userId,
              status: 'offline',
              lastSeen: Date.now(),
            });
          });
        }
      } catch (error) {
        logger.error(`Socket disconnect error: ${error.message}`);
      }
    });
  });
};

module.exports = configureSocket;