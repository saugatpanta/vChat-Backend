const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced CORS configuration
const allowedOrigins = [
  'https://v-chat-frontend-gamma.vercel.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.options('*', cors(corsOptions));

// File upload configuration
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|mp3|mp4|wav/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only image, audio and video files are allowed!'));
    }
  }
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/vchat', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
  userId: { type: String, default: uuidv4, unique: true },
  username: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/ 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email!`
    }
  },
  password: { type: String, required: true, minlength: 8 },
  avatar: { type: String, default: 'default-avatar.png' },
  status: { type: String, enum: ['online', 'offline', 'away'], default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
  refreshToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
  }],
  settings: {
    theme: { type: String, enum: ['light', 'dark', 'system'], default: 'system' },
    notifications: { type: Boolean, default: true },
    privacy: {
      lastSeen: { type: String, enum: ['everyone', 'friends', 'none'], default: 'friends' },
      profilePhoto: { type: String, enum: ['everyone', 'friends', 'none'], default: 'friends' }
    }
  }
}, { timestamps: true });

// Message Schema
const messageSchema = new mongoose.Schema({
  messageId: { type: String, default: uuidv4, unique: true },
  conversationId: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String },
  type: { type: String, enum: ['text', 'voice', 'image', 'video', 'file'], default: 'text' },
  fileUrl: { type: String },
  read: { type: Boolean, default: false },
  delivered: { type: Boolean, default: false },
  reactions: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji: { type: String }
  }]
}, { timestamps: true });

// Call Schema
const callSchema = new mongoose.Schema({
  callId: { type: String, default: uuidv4, unique: true },
  caller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['voice', 'video'], required: true },
  status: { type: String, enum: ['initiated', 'ongoing', 'missed', 'completed', 'rejected'], default: 'initiated' },
  startedAt: { type: Date },
  endedAt: { type: Date },
  duration: { type: Number } // in seconds
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Call = mongoose.model('Call', callSchema);

// JWT Helper Functions
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId },
    process.env.ACCESS_TOKEN_SECRET || 'your_access_token_secret',
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId },
    process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret',
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Authentication Middleware
const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your_access_token_secret');
    const user = await User.findOne({ userId: decoded.userId });
    
    if (!user) {
      return res.status(403).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });
    
    const { accessToken, refreshToken } = generateTokens(user.userId);
    
    user.refreshToken = refreshToken;
    await user.save();
    
    res.status(201).json({ 
      accessToken,
      refreshToken,
      user: { 
        userId: user.userId,
        username: user.username, 
        email: user.email, 
        avatar: user.avatar,
        status: user.status
      } 
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const { accessToken, refreshToken } = generateTokens(user.userId);
    
    user.status = 'online';
    user.lastSeen = new Date();
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({ 
      accessToken,
      refreshToken,
      user: { 
        userId: user.userId,
        username: user.username, 
        email: user.email, 
        avatar: user.avatar, 
        status: user.status,
        settings: user.settings
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }
    
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret');
    const user = await User.findOne({ userId: decoded.userId, refreshToken });
    
    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }
    
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.userId);
    
    user.refreshToken = newRefreshToken;
    await user.save();
    
    res.json({ 
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();
    
    // In a real app, you would send an email with the reset token
    // For this example, we'll just return it
    res.json({ 
      message: 'Password reset token generated',
      resetToken 
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }
    
    const user = await User.findOne({ 
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();
    
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Routes
app.get('/api/users', authenticateJWT, async (req, res) => {
  try {
    const users = await User.find({ userId: { $ne: req.user.userId } })
      .select('-password -refreshToken -resetToken -resetTokenExpiry -friendRequests -friends');
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/user/:userId', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.userId })
      .select('-password -refreshToken -resetToken -resetTokenExpiry');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check privacy settings
    if (req.params.userId !== req.user.userId) {
      if (user.settings.privacy.profilePhoto === 'friends') {
        const isFriend = req.user.friends.includes(user._id);
        if (!isFriend) {
          user.avatar = 'default-avatar.png';
        }
      } else if (user.settings.privacy.profilePhoto === 'none') {
        user.avatar = 'default-avatar.png';
      }
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/user', authenticateJWT, upload.single('avatar'), async (req, res) => {
  try {
    const { username, email, status } = req.body;
    const updates = {};
    
    if (username) updates.username = username;
    if (email) updates.email = email;
    if (status) updates.status = status;
    
    if (req.file) {
      updates.avatar = `/uploads/${req.file.filename}`;
      // Delete old avatar if it's not the default one
      if (req.user.avatar !== 'default-avatar.png') {
        const oldAvatarPath = path.join(__dirname, 'public', req.user.avatar);
        if (fs.existsSync(oldAvatarPath)) {
          fs.unlinkSync(oldAvatarPath);
        }
      }
    }
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    ).select('-password -refreshToken -resetToken -resetTokenExpiry');
    
    res.json(user);
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/user/settings', authenticateJWT, async (req, res) => {
  try {
    const { theme, notifications, privacy } = req.body;
    
    const updates = {};
    if (theme) updates['settings.theme'] = theme;
    if (notifications !== undefined) updates['settings.notifications'] = notifications;
    if (privacy) {
      if (privacy.lastSeen) updates['settings.privacy.lastSeen'] = privacy.lastSeen;
      if (privacy.profilePhoto) updates['settings.privacy.profilePhoto'] = privacy.profilePhoto;
    }
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true }
    ).select('-password -refreshToken -resetToken -resetTokenExpiry');
    
    res.json(user);
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Friend Routes
app.post('/api/friends/request', authenticateJWT, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }
    
    if (userId === req.user.userId) {
      return res.status(400).json({ message: 'Cannot send friend request to yourself' });
    }
    
    const receiver = await User.findOne({ userId });
    if (!receiver) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if already friends
    if (req.user.friends.includes(receiver._id)) {
      return res.status(400).json({ message: 'Already friends' });
    }
    
    // Check if request already exists
    const existingRequest = receiver.friendRequests.find(
      req => req.from.equals(req.user._id) && req.status === 'pending'
    );
    
    if (existingRequest) {
      return res.status(400).json({ message: 'Friend request already sent' });
    }
    
    receiver.friendRequests.push({
      from: req.user._id,
      status: 'pending'
    });
    
    await receiver.save();
    
    // Emit notification to receiver via socket.io
    io.to(receiver.userId).emit('friendRequest', {
      from: req.user.userId,
      username: req.user.username,
      avatar: req.user.avatar
    });
    
    res.json({ message: 'Friend request sent' });
  } catch (error) {
    console.error('Friend request error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/friends/respond', authenticateJWT, async (req, res) => {
  try {
    const { userId, accept } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }
    
    const sender = await User.findOne({ userId });
    if (!sender) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Find the friend request
    const requestIndex = req.user.friendRequests.findIndex(
      req => req.from.equals(sender._id) && req.status === 'pending'
    );
    
    if (requestIndex === -1) {
      return res.status(404).json({ message: 'Friend request not found' });
    }
    
    // Update request status
    req.user.friendRequests[requestIndex].status = accept ? 'accepted' : 'rejected';
    
    if (accept) {
      // Add to friends list if accepted
      if (!req.user.friends.includes(sender._id)) {
        req.user.friends.push(sender._id);
      }
      if (!sender.friends.includes(req.user._id)) {
        sender.friends.push(req.user._id);
      }
    }
    
    await req.user.save();
    await sender.save();
    
    // Emit response to sender via socket.io
    io.to(sender.userId).emit('friendRequestResponse', {
      to: req.user.userId,
      accepted: accept
    });
    
    res.json({ 
      message: accept ? 'Friend request accepted' : 'Friend request rejected',
      friend: accept ? {
        userId: sender.userId,
        username: sender.username,
        avatar: sender.avatar,
        status: sender.status
      } : null
    });
  } catch (error) {
    console.error('Friend response error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/friends', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('friends', 'userId username avatar status lastSeen settings.privacy.lastSeen')
      .select('friends');
    
    // Filter friends based on privacy settings
    const friends = user.friends.map(friend => {
      const friendObj = friend.toObject();
      
      if (friend.settings.privacy.lastSeen === 'friends') {
        friendObj.lastSeen = friend.lastSeen;
      } else if (friend.settings.privacy.lastSeen === 'none') {
        delete friendObj.lastSeen;
      }
      
      delete friendObj.settings;
      return friendObj;
    });
    
    res.json(friends);
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/friends/requests', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('friendRequests.from', 'userId username avatar')
      .select('friendRequests');
    
    const requests = user.friendRequests
      .filter(req => req.status === 'pending')
      .map(req => ({
        requestId: req._id,
        from: req.from,
        createdAt: req.createdAt
      }));
    
    res.json(requests);
  } catch (error) {
    console.error('Get friend requests error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/friends/:userId', authenticateJWT, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const friend = await User.findOne({ userId });
    if (!friend) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Remove from friends list
    req.user.friends = req.user.friends.filter(id => !id.equals(friend._id));
    friend.friends = friend.friends.filter(id => !id.equals(req.user._id));
    
    // Remove any pending requests
    req.user.friendRequests = req.user.friendRequests.filter(
      req => !req.from.equals(friend._id)
    );
    friend.friendRequests = friend.friendRequests.filter(
      req => !req.from.equals(req.user._id)
    );
    
    await req.user.save();
    await friend.save();
    
    // Notify the other user via socket.io
    io.to(friend.userId).emit('friendRemoved', {
      userId: req.user.userId
    });
    
    res.json({ message: 'Friend removed' });
  } catch (error) {
    console.error('Remove friend error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Message Routes
app.get('/api/messages/conversations', authenticateJWT, async (req, res) => {
  try {
    // Get all unique conversations for the user
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: req.user._id },
            { receiver: req.user._id }
          ]
        }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ["$sender", req.user._id] },
              "$receiver",
              "$sender"
            ]
          },
          lastMessage: { $last: "$$ROOT" },
          unreadCount: {
            $sum: {
              $cond: [
                { $and: [
                  { $eq: ["$receiver", req.user._id] },
                  { $eq: ["$read", false] }
                ]},
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$user.userId',
          username: '$user.username',
          avatar: '$user.avatar',
          status: '$user.status',
          lastMessage: {
            messageId: '$lastMessage.messageId',
            content: '$lastMessage.content',
            type: '$lastMessage.type',
            createdAt: '$lastMessage.createdAt',
            read: '$lastMessage.read'
          },
          unreadCount: 1
        }
      },
      {
        $sort: { 'lastMessage.createdAt': -1 }
      }
    ]);
    
    res.json(conversations);
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/:userId', authenticateJWT, async (req, res) => {
  try {
    const { userId } = req.params;
    const { before, limit = 20 } = req.query;
    
    const otherUser = await User.findOne({ userId });
    if (!otherUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const query = {
      $or: [
        { sender: req.user._id, receiver: otherUser._id },
        { sender: otherUser._id, receiver: req.user._id }
      ]
    };
    
    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }
    
    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .populate('sender receiver', 'userId username avatar')
      .lean();
    
    // Mark messages as read
    await Message.updateMany(
      {
        receiver: req.user._id,
        sender: otherUser._id,
        read: false
      },
      { $set: { read: true } }
    );
    
    // Notify the other user that messages were read
    io.to(otherUser.userId).emit('messagesRead', {
      by: req.user.userId
    });
    
    res.json(messages.reverse());
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages', authenticateJWT, upload.single('file'), async (req, res) => {
  try {
    const { receiverId, content, type } = req.body;
    
    if (!receiverId) {
      return res.status(400).json({ message: 'Receiver ID is required' });
    }
    
    const receiver = await User.findOne({ userId: receiverId });
    if (!receiver) {
      return res.status(404).json({ message: 'Receiver not found' });
    }
    
    // Generate conversation ID (sorted user IDs concatenated)
    const conversationId = [req.user.userId, receiverId].sort().join('_');
    
    const messageData = {
      conversationId,
      sender: req.user._id,
      receiver: receiver._id,
      content,
      type: type || 'text'
    };
    
    if (req.file) {
      messageData.fileUrl = `/uploads/${req.file.filename}`;
      messageData.type = type || req.file.mimetype.split('/')[0]; // 'image', 'video', 'audio'
    }
    
    const message = await Message.create(messageData);
    const populatedMessage = await Message.populate(message, {
      path: 'sender receiver',
      select: 'userId username avatar'
    });
    
    // Emit to both users via socket.io
    io.to(req.user.userId).emit('messageSent', populatedMessage);
    io.to(receiverId).emit('receiveMessage', populatedMessage);
    
    res.status(201).json(populatedMessage);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages/react', authenticateJWT, async (req, res) => {
  try {
    const { messageId, emoji } = req.body;
    
    if (!messageId || !emoji) {
      return res.status(400).json({ message: 'Message ID and emoji are required' });
    }
    
    const message = await Message.findOne({ messageId });
    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }
    
    // Check if user already reacted
    const existingReactionIndex = message.reactions.findIndex(
      r => r.userId.equals(req.user._id)
    );
    
    if (existingReactionIndex !== -1) {
      // Remove reaction if same emoji
      if (message.reactions[existingReactionIndex].emoji === emoji) {
        message.reactions.splice(existingReactionIndex, 1);
      } else {
        // Update reaction
        message.reactions[existingReactionIndex].emoji = emoji;
      }
    } else {
      // Add new reaction
      message.reactions.push({
        userId: req.user._id,
        emoji
      });
    }
    
    await message.save();
    
    const populatedMessage = await Message.populate(message, {
      path: 'sender receiver reactions.userId',
      select: 'userId username avatar'
    });
    
    // Notify both users
    io.to(message.sender.userId).emit('messageReaction', populatedMessage);
    io.to(message.receiver.userId).emit('messageReaction', populatedMessage);
    
    res.json(populatedMessage);
  } catch (error) {
    console.error('React to message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Call Routes
app.post('/api/calls/initiate', authenticateJWT, async (req, res) => {
  try {
    const { receiverId, type } = req.body;
    
    if (!receiverId || !type) {
      return res.status(400).json({ message: 'Receiver ID and call type are required' });
    }
    
    const receiver = await User.findOne({ userId: receiverId });
    if (!receiver) {
      return res.status(404).json({ message: 'Receiver not found' });
    }
    
    // Check if receiver is online
    if (receiver.status !== 'online') {
      return res.status(400).json({ message: 'Receiver is offline' });
    }
    
    // Create call record
    const call = await Call.create({
      caller: req.user._id,
      receiver: receiver._id,
      type,
      status: 'initiated'
    });
    
    // Emit call initiation to receiver via socket.io
    io.to(receiverId).emit('incomingCall', {
      callId: call.callId,
      caller: {
        userId: req.user.userId,
        username: req.user.username,
        avatar: req.user.avatar
      },
      type
    });
    
    res.json({ 
      callId: call.callId,
      status: 'initiated'
    });
  } catch (error) {
    console.error('Initiate call error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/calls/respond', authenticateJWT, async (req, res) => {
  try {
    const { callId, accept } = req.body;
    
    if (!callId) {
      return res.status(400).json({ message: 'Call ID is required' });
    }
    
    const call = await Call.findOne({ callId });
    if (!call) {
      return res.status(404).json({ message: 'Call not found' });
    }
    
    if (!call.receiver.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized to respond to this call' });
    }
    
    if (call.status !== 'initiated') {
      return res.status(400).json({ message: 'Call already responded to' });
    }
    
    call.status = accept ? 'ongoing' : 'rejected';
    call.startedAt = accept ? new Date() : undefined;
    
    await call.save();
    
    // Emit response to caller via socket.io
    io.to(call.caller.userId).emit('callResponse', {
      callId,
      accepted: accept,
      by: req.user.userId
    });
    
    res.json({ 
      callId,
      status: call.status
    });
  } catch (error) {
    console.error('Respond to call error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/calls/end', authenticateJWT, async (req, res) => {
  try {
    const { callId } = req.body;
    
    if (!callId) {
      return res.status(400).json({ message: 'Call ID is required' });
    }
    
    const call = await Call.findOne({ callId });
    if (!call) {
      return res.status(404).json({ message: 'Call not found' });
    }
    
    if (!call.caller.equals(req.user._id) && !call.receiver.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized to end this call' });
    }
    
    if (call.status === 'completed' || call.status === 'rejected') {
      return res.status(400).json({ message: 'Call already ended' });
    }
    
    call.status = 'completed';
    call.endedAt = new Date();
    call.duration = Math.floor((call.endedAt - call.startedAt) / 1000);
    
    await call.save();
    
    // Emit call end to both parties via socket.io
    const otherUserId = call.caller.equals(req.user._id) ? call.receiver.userId : call.caller.userId;
    io.to(otherUserId).emit('callEnded', {
      callId,
      by: req.user.userId,
      duration: call.duration
    });
    
    res.json({ 
      callId,
      status: call.status,
      duration: call.duration
    });
  } catch (error) {
    console.error('End call error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/calls/history', authenticateJWT, async (req, res) => {
  try {
    const calls = await Call.find({
      $or: [
        { caller: req.user._id },
        { receiver: req.user._id }
      ]
    })
    .sort({ createdAt: -1 })
    .populate('caller receiver', 'userId username avatar')
    .limit(20);
    
    res.json(calls);
  } catch (error) {
    console.error('Get call history error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    dbStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'public')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Socket.IO setup
const io = new Server(server, {
  cors: {
