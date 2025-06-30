const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  conversation: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation',
    required: true,
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  text: {
    type: String,
    trim: true,
  },
  media: [
    {
      url: String,
      type: {
        type: String,
        enum: ['image', 'video', 'audio', 'file'],
      },
      filename: String,
      size: Number,
    },
  ],
  isRead: {
    type: Boolean,
    default: false,
  },
  readAt: {
    type: Date,
  },
  reactions: [
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
      emoji: String,
    },
  ],
  deletedFor: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  ],
  call: {
    type: {
      type: String,
      enum: ['voice', 'video'],
    },
    duration: Number,
    status: {
      type: String,
      enum: ['missed', 'answered', 'declined'],
    },
  },
}, {
  timestamps: true,
});

// Indexes for faster querying
messageSchema.index({ conversation: 1, createdAt: -1 });
messageSchema.index({ sender: 1, recipient: 1 });

module.exports = mongoose.model('Message', messageSchema);