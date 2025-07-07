require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIO = require('socket.io');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced CORS configuration
const allowedOrigins = [
  process.env.FRONTEND_URL,
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
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Enhanced User Schema
const userSchema = new mongoose.Schema({
  userId: { type: String, default: uuidv4, unique: true },
  username: { type: String, required: true, unique: true, trim: true },
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
  resetTokenExpiry: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  messageId: { type: String, default: uuidv4, unique: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'voice', 'image', 'video'], default: 'text' },
  read: { type: Boolean, default: false },
  delivered: { type: Boolean, default: false }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// JWT Helper Functions
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
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
    
    // Save refresh token to DB
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
    
    // Update user status and refresh token
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
        status: user.status 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/token', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }
  
  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }
    
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err || user.userId !== decoded.userId) {
        return res.status(403).json({ message: 'Invalid refresh token' });
      }
      
      const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.userId);
      
      // Update refresh token in DB
      user.refreshToken = newRefreshToken;
      user.save();
      
      res.json({ accessToken, refreshToken: newRefreshToken });
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected Routes
app.get('/api/users', authenticateJWT, async (req, res) => {
  try {
    const users = await User.find({ userId: { $ne: req.user.userId } })
      .select('-password -refreshToken -resetToken -resetTokenExpiry');
    
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
    dbStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// 404 Handler for API routes
app.use('/api', (req, res) => {
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
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  
  // Heartbeat monitoring
  let heartbeatInterval = setInterval(() => {
    socket.emit('ping');
  }, 20000);
  
  socket.on('pong', () => {
    console.log(`Heartbeat received from ${socket.id}`);
  });
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      const user = await User.findOne({ userId: decoded.userId });
      
      if (!user) {
        socket.emit('authentication_error', 'User not found');
        return socket.disconnect();
      }
      
      socket.userId = user.userId;
      socket.join(user.userId);
      console.log(`User ${user.username} authenticated`);
      
      // Update user status
      user.status = 'online';
      user.lastSeen = new Date();
      await user.save();
      
      socket.emit('authenticated');
    } catch (error) {
      socket.emit('authentication_error', 'Invalid token');
      socket.disconnect();
    }
  });
  
  socket.on('disconnect', async () => {
    console.log(`Client disconnected: ${socket.id}`);
    clearInterval(heartbeatInterval);
    
    if (socket.userId) {
      const user = await User.findOne({ userId: socket.userId });
      if (user) {
        user.status = 'offline';
        user.lastSeen = new Date();
        await user.save();
      }
    }
  });
  
  // Message handling
  socket.on('sendMessage', async (messageData) => {
    try {
      if (!socket.userId) {
        return socket.emit('error', 'Not authenticated');
      }
      
      const { receiverId, content, type } = messageData;
      
      const message = await Message.create({
        sender: socket.userId,
        receiver: receiverId,
        content,
        type
      });
      
      const populatedMessage = await Message.populate(message, {
        path: 'sender receiver',
        select: 'userId username avatar'
      });
      
      // Emit to sender and receiver
      io.to(socket.userId).emit('messageSent', populatedMessage);
      io.to(receiverId).emit('receiveMessage', populatedMessage);
    } catch (error) {
      console.error('Message send error:', error);
      socket.emit('error', 'Failed to send message');
    }
  });
});

// Graceful shutdown
const shutdown = async () => {
  console.log('Shutting down gracefully...');
  
  try {
    // Update all online users to offline
    await User.updateMany(
      { status: 'online' },
      { $set: { status: 'offline', lastSeen: new Date() } }
    );
    
    // Close server
    server.close(() => {
      console.log('Server closed');
      
      // Close MongoDB connection
      mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed');
        process.exit(0);
      });
    });
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
