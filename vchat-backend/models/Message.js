const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  conversation: {
    type: mongoose.Schema.ObjectId,
    ref: 'Conversation',
    required: true,
  },
  sender: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true,
  },
  content: {
    type: String,
    required: function () {
      return !this.media; // Content is required if there's no media
    },
  },
  type: {
    type: String,
    enum: ['text', 'image', 'video', 'audio', 'file'],
    default: 'text',
  },
  media: {
    url: String,
    publicId: String,
  },
  readBy: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Add text index for search functionality
MessageSchema.index({ content: 'text' });

module.exports = mongoose.model('Message', MessageSchema);