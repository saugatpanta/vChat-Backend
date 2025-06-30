const mongoose = require('mongoose');

const StorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    maxlength: [200, 'Story content cannot be more than 200 characters']
  },
  mediaUrl: {
    type: String
  },
  mediaType: {
    type: String,
    enum: ['text', 'image', 'video'],
    default: 'text'
  },
  viewers: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User'
    }
  ],
  expiresAt: {
    type: Date,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for automatic deletion of expired stories
StorySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Story', StorySchema);