require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIO = require('socket.io');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced CORS configuration
const corsOptions = {
  origin: [
    process.env.FRONTEND_URL, // Your Vercel frontend URL
    'http://localhost:3000'   // For local development
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

// Remove static file serving since frontend is on Vercel
// app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection (updated without deprecated options)
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit if DB connection fails
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: 'default-avatar.png' },
  status: { type: String, default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
  resetToken: String,
  resetTokenExpiry: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'voice', 'image'], default: 'text' },
  read: { type: Boolean, default: false }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// Authentication Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate input
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
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    res.status(201).json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        avatar: user.avatar 
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
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    // Update user status
    user.status = 'online';
    user.lastSeen = new Date();
    await user.save();
    
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        avatar: user.avatar, 
        status: user.status 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Password Reset Routes
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal whether email exists for security
      return res.json({ message: 'If an account exists, a reset link has been sent' });
    }
    
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // In production, you would send an email here
    console.log('Reset token:', resetToken); // For development only
    
    res.json({ message: 'If an account exists, a reset link has been sent' });
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
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ 
      _id: decoded.id, 
      resetToken: token, 
      resetTokenExpiry: { $gt: Date.now() } 
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Chat Routes with improved error handling
app.get('/api/messages/:userId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization token required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { userId } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    
    const messages = await Message.find({
      $or: [
        { sender: decoded.id, receiver: userId },
        { sender: userId, receiver: decoded.id }
      ]
    })
    .sort({ createdAt: 1 })
    .populate('sender receiver', 'username avatar');
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization token required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const users = await User.find({ _id: { $ne: decoded.id } })
      .select('-password -resetToken -resetTokenExpiry');
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    dbStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Updated catch-all route for API
app.get('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'API endpoint not found',
    documentation: 'https://github.com/your-repo/docs' 
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Enhanced Socket.IO setup
const io = socketIO(server, {
  cors: {
    origin: corsOptions.origin,
    methods: corsOptions.methods,
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Socket.IO connection handling with improved reliability
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  
  // Heartbeat monitoring
  let heartbeatInterval = setInterval(() => {
    socket.emit('ping');
  }, 20000);
  
  socket.on('pong', () => {
    console.log(`Heartbeat received from ${socket.id}`);
  });
  
  socket.on('join', (userId) => {
    if (!userId) {
      console.warn('No userId provided for join');
      return;
    }
    socket.join(userId);
    console.log(`User ${userId} joined room`);
  });
  
  socket.on('sendMessage', async ({ senderId, receiverId, content, type }) => {
    try {
      if (!senderId || !receiverId || !content) {
        console.warn('Invalid message data received');
        return;
      }
      
      const message = await Message.create({
        sender: senderId,
        receiver: receiverId,
        content,
        type
      });
      
      const populatedMessage = await Message.populate(message, {
        path: 'sender receiver',
        select: 'username avatar'
      });
      
      io.to(receiverId).emit('receiveMessage', populatedMessage);
      socket.emit('messageSent', populatedMessage);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });
  
  // Enhanced call handling
  socket.on('callUser', ({ from, to, signal, callType }) => {
    if (!from || !to || !signal || !callType) {
      console.warn('Invalid call data received');
      return;
    }
    io.to(to).emit('incomingCall', { from, signal, callType });
  });
  
  socket.on('acceptCall', ({ to, signal }) => {
    if (!to || !signal) {
      console.warn('Invalid accept call data received');
      return;
    }
    io.to(to).emit('callAccepted', signal);
  });
  
  socket.on('rejectCall', ({ to }) => {
    if (!to) {
      console.warn('Invalid reject call data received');
      return;
    }
    io.to(to).emit('callRejected');
  });
  
  socket.on('endCall', ({ to }) => {
    if (!to) {
      console.warn('Invalid end call data received');
      return;
    }
    io.to(to).emit('callEnded');
  });
  
  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
    clearInterval(heartbeatInterval);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
