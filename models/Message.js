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
  text: {
    type: String,
    maxlength: [1000, 'Message cannot be more than 1000 characters']
  },
  media: {
    type: String
  },
  isMedia: {
    type: Boolean,
    default: false
  },
  isCall: {
    type: Boolean,
    default: false
  },
  isVideoCall: {
    type: Boolean,
    default: false
  },
  callStatus: {
    type: String,
    enum: ['initiated', 'answered', 'rejected', 'missed', 'ended'],
    default: 'initiated'
  },
  read: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Message', MessageSchema);