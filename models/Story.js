const mongoose = require('mongoose');

const StorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  media: {
    url: String,
    type: {
      type: String,
      enum: ['image', 'video'],
      required: true
    }
  },
  caption: {
    type: String,
    maxlength: 100
  },
  views: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

StorySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Story', StorySchema);