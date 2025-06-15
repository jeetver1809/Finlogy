const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
require('dotenv').config();

// Import Passport configuration
require('./config/passport');

// Import routes
const authRoutes = require('./routes/auth');
const expenseRoutes = require('./routes/expenses');
const incomeRoutes = require('./routes/income');
const budgetRoutes = require('./routes/budgets');
const analyticsRoutes = require('./routes/analytics');
const aiRoutes = require('./routes/ai');
const feedbackRoutes = require('./routes/feedback');

// Import middleware
const errorHandler = require('./middleware/errorHandler');

const app = express();

// CORS configuration - MUST come before rate limiting and other middleware
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      console.log('✅ CORS: No origin (non-browser request)');
      return callback(null, true);
    }

    const allowedOrigins = [
      process.env.CLIENT_URL,
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:5175',
      'http://localhost:5176',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5174',
      'http://127.0.0.1:5001',
      // Add your Vercel frontend URL here after deployment
      'https://your-vercel-app.vercel.app'
    ].filter(Boolean); // Remove any undefined values

    // Allow all subdomains of localhost in development
    if (process.env.NODE_ENV === 'development' && 
        (origin.match(/^https?:\/\/localhost(:[0-9]+)?$/) || 
         origin.match(/^https?:\/\/127\.0\.0\.1(:[0-9]+)?$/))) {
      console.log(`✅ CORS: Allowing localhost origin: ${origin}`);
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      console.log(`✅ CORS: Allowing whitelisted origin: ${origin}`);
      return callback(null, true);
    }

    console.log(`❌ CORS: Blocking origin: ${origin}`);
    console.log('Allowed origins:', allowedOrigins);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'Pragma'
  ],
  exposedHeaders: ['Authorization', 'Content-Length', 'X-Foo', 'X-Bar'],
  optionsSuccessStatus: 200, // Some legacy browsers choke on 204
  preflightContinue: false,
  maxAge: 86400 // 24 hours
};

// Apply CORS with the above configuration
app.use(cors(corsOptions));

// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Security middleware with CSP for Google OAuth
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://accounts.google.com",
        "https://apis.google.com",
        "https://www.google.com"
      ],
      connectSrc: [
        "'self'",
        "https://accounts.google.com",
        "https://oauth2.googleapis.com",
        "https://www.googleapis.com"
      ],
      frameSrc: [
        "'self'",
        "https://accounts.google.com",
        "https://apis.google.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com"
      ],
      fontSrc: ["'self'"],
      imgSrc: ["'self'"],
    },
  },
}));

// Rate limiting - More permissive for development
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000, // Increased to 1000 for development
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skip: (req) => {
    // Skip rate limiting for:
    // 1. OPTIONS requests (CORS preflight)
    // 2. OAuth callback endpoints
    // 3. Health check endpoint
    const skipPaths = [
      '/api/auth/google',
      '/api/auth/google/callback',
      '/api/auth/oauth/success',
      '/api/auth/oauth/failure',
      '/api/health'
    ];
    
    return req.method === 'OPTIONS' || 
           skipPaths.some(path => req.path.startsWith(path));
  }
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration for OAuth with MongoDB store
let sessionStore;
try {
  if (!process.env.MONGODB_URI) {
    console.warn('⚠️  MONGODB_URI is not set. Using in-memory session store (not recommended for production).');
  } else {
    sessionStore = MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions',
      autoRemove: 'interval',
      autoRemoveInterval: 60 * 24, // Remove expired sessions every 24 hours
      ttl: 24 * 60 * 60, // Session TTL: 24 hours in seconds
      touchAfter: 12 * 3600, // Time period in seconds to resave the session to the store
      mongoOptions: {
        retryWrites: true,
        w: 'majority'
      }
    });
    
    // Log when the session store is connected
    sessionStore.on('create', () => {
      console.log('✅ MongoDB session store connected successfully');
    });
    
    sessionStore.on('error', (error) => {
      console.error('❌ MongoDB session store error:', error);
    });
  }
} catch (error) {
  console.error('❌ Failed to initialize MongoDB session store:', error);
  process.exit(1);
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: process.env.MONGODB_URI ? sessionStore : new session.MemoryStore(),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'lax'
  },
  proxy: process.env.NODE_ENV === 'production' // Trust the reverse proxy in production
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB with enhanced error handling
const connectToMongoDB = async () => {
  const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/finance-tracker';
  
  try {
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
    });
    
    console.log('✅ Connected to MongoDB');
    
    // Log MongoDB connection events
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connection is open');
    });
    
    mongoose.connection.on('error', (err) => {
      console.error('Mongoose connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose connection is disconnected');
    });
    
    // Close the Mongoose connection when the Node process ends
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('Mongoose connection is disconnected due to application termination');
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    // Exit process with failure if we can't connect to MongoDB
    process.exit(1);
  }
};

// Initialize MongoDB connection
connectToMongoDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/expenses', expenseRoutes);
app.use('/api/income', incomeRoutes);
app.use('/api/budgets', budgetRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/feedback', feedbackRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Finance Tracker API is running',
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
});

// Error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
