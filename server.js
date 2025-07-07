require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced CORS configuration
const allowedOrigins = [
  'https://v-chat-frontend.vercel.app',
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
app.options('*', cors(corsOptions));

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
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your_access_token_secret', (err, user) => {
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
        status: user.status 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

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

app.get('/api/messages/:userId', authenticateJWT, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.user.userId, receiver: req.params.userId },
        { sender: req.params.userId, receiver: req.user.userId }
      ]
    })
    .sort('createdAt')
    .populate('sender receiver', 'userId username avatar');
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
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
  app.use(express.static(path.join(__dirname, 'client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
  });
}

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Socket.IO setup
const io = new Server(server, {
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
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your_access_token_secret');
      const user = await User.findOne({ userId: decoded.userId });
      
      if (!user) {
        socket.emit('authentication_error', 'User not found');
        return socket.disconnect();
      }
      
      socket.userId = user.userId;
      socket.join(user.userId);
      
      user.status = 'online';
      user.lastSeen = new Date();
      await user.save();
      
      io.emit('userStatusChanged', {
        userId: user.userId,
        status: 'online'
      });
      
      socket.emit('authenticated');
    } catch (error) {
      socket.emit('authentication_error', 'Invalid token');
      socket.disconnect();
    }
  });
  
  socket.on('disconnect', async () => {
    console.log(`Client disconnected: ${socket.id}`);
    
    if (socket.userId) {
      const user = await User.findOne({ userId: socket.userId });
      if (user) {
        user.status = 'offline';
        user.lastSeen = new Date();
        await user.save();
        
        io.emit('userStatusChanged', {
          userId: user.userId,
          status: 'offline'
        });
      }
    }
  });
  
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
      
      io.to(socket.userId).emit('messageSent', populatedMessage);
      io.to(receiverId).emit('receiveMessage', populatedMessage);
    } catch (error) {
      console.error('Message send error:', error);
      socket.emit('error', 'Failed to send message');
    }
  });
  
  socket.on('typing', (data) => {
    if (socket.userId && data.receiverId) {
      io.to(data.receiverId).emit('typing', {
        senderId: socket.userId,
        isTyping: data.isTyping
      });
    }
  });
});

// Graceful shutdown
const shutdown = async () => {
  console.log('Shutting down gracefully...');
  
  try {
    await User.updateMany(
      { status: 'online' },
      { $set: { status: 'offline', lastSeen: new Date() } }
    );
    
    server.close(() => {
      console.log('Server closed');
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
