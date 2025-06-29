const mongoose = require('mongoose');

const ReactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true,
  },
  reaction: {
    type: String,
    required: true,
    enum: ['like', 'love', 'haha', 'wow', 'sad', 'angry'],
  },
});

const StorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true,
  },
  media: {
    url: {
      type: String,
      required: true,
    },
    publicId: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      enum: ['image', 'video'],
      required: true,
    },
  },
  caption: {
    type: String,
    maxlength: [100, 'Caption cannot be more than 100 characters'],
  },
  duration: {
    type: Number,
    default: 24, // hours
    min: 1,
    max: 48,
  },
  views: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
    },
  ],
  reactions: [ReactionSchema],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for better query performance
StorySchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('Story', StorySchema);