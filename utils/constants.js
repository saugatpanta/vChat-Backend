module.exports = {
  USER_STATUS: {
    ONLINE: 'online',
    OFFLINE: 'offline',
    AWAY: 'away',
    BUSY: 'busy'
  },
  MESSAGE_TYPES: {
    TEXT: 'text',
    IMAGE: 'image',
    VIDEO: 'video',
    AUDIO: 'audio',
    FILE: 'file'
  },
  NOTIFICATION_TYPES: {
    MESSAGE: 'message',
    FOLLOW: 'follow',
    LIKE: 'like',
    COMMENT: 'comment',
    STORY: 'story'
  },
  REACTIONS: ['like', 'love', 'haha', 'wow', 'sad', 'angry'],
  THEMES: ['light', 'dark', 'system'],
  PRIVACY_SETTINGS: ['public', 'private', 'friends'],
  FILE_SIZE_LIMITS: {
    IMAGE: 5 * 1024 * 1024, // 5MB
    VIDEO: 50 * 1024 * 1024, // 50MB
    AUDIO: 10 * 1024 * 1024, // 10MB
    FILE: 20 * 1024 * 1024 // 20MB
  }
};