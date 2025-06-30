const mongoose = require('mongoose');

const ConversationSchema = new mongoose.Schema({
  participants: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: true
    }
  ],
  isGroup: {
    type: Boolean,
    default: false
  },
  groupName: {
    type: String,
    maxlength: [50, 'Group name cannot be more than 50 characters']
  },
  groupAdmin: {
    type: mongoose.Schema.ObjectId,
    ref: 'User'
  },
  groupImage: {
    type: String
  },
  lastMessage: {
    type: mongoose.Schema.ObjectId,
    ref: 'Message'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Update updatedAt when conversation changes
ConversationSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Cascade delete messages when conversation is deleted
ConversationSchema.pre('remove', async function(next) {
  await this.model('Message').deleteMany({ conversation: this._id });
  next();
});

module.exports = mongoose.model('Conversation', ConversationSchema);