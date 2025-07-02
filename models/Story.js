const mongoose = require('mongoose');

const StorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    maxlength: [200, 'Story text cannot be more than 200 characters']
  },
  media: {
    type: String,
    required: [true, 'Please upload a media file for your story']
  },
  isMedia: {
    type: Boolean,
    default: true
  },
  duration: {
    type: Number,
    default: 24 // hours
  },
  viewers: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User'
    }
  ],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Story', StorySchema);