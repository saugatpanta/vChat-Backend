const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  conversation: {
    type: mongoose.Schema.ObjectId,
    ref: 'Conversation',
    required: true
  },
  sender: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['text', 'image', 'video', 'audio', 'file', 'location'],
    default: 'text'
  },
  readBy: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User'
    }
  ],
  deleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Reverse populate with virtuals
MessageSchema.virtual('replies', {
  ref: 'Message',
  localField: '_id',
  foreignField: 'replyTo',
  justOne: false
});

// Cascade delete replies when a message is deleted
MessageSchema.pre('remove', async function(next) {
  await this.model('Message').deleteMany({ replyTo: this._id });
  next();
});

module.exports = mongoose.model('Message', MessageSchema);