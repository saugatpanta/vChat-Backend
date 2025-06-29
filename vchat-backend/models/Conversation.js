const mongoose = require('mongoose');

const ConversationSchema = new mongoose.Schema({
  participants: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: true,
    },
  ],
  lastMessage: {
    type: mongoose.Schema.ObjectId,
    ref: 'Message',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Update the updatedAt field before saving
ConversationSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Ensure unique participants combination
ConversationSchema.index({ participants: 1 }, { unique: true });

module.exports = mongoose.model('Conversation', ConversationSchema);