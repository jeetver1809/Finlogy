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

// ========================
// CORS Configuration
// ========================
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      console.log('✅ CORS: No origin (non-browser request)');
      return callback(null, true);
    }

    const allowedOrigins = [
      process.env.CLIENT_URL,
      // Development URLs
      ...(process.env.NODE_ENV === 'development' ? [
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
        'http://localhost:5176',
        'http://127.0.0.1:5173',
        'http://127.0.0.1:5174',
        'http://127.0.0.1:5001'
      ] : []),
      // Production frontend URL
      'https://finlogy-frontend.onrender.com'
    ].filter(Boolean);

    // Allow all subdomains of localhost in development
    if (process.env.NODE_ENV === 'development' && 
        (origin.match(/^https?:\/\/localhost(:\d+)?$/) || 
         origin.match(/^https?:\/\/127\.0\.0\.1(:\d+)?$/))) {
      console.log(`✅ CORS: Allowing localhost origin: ${origin}`);
      return callback(null, true);
    }

    if (allowedOrigins.some(allowedOrigin => 
      origin === allowedOrigin || 
      origin.startsWith(allowedOrigin.replace(/\*$/, ''))
    )) {
      console.log(`✅ CORS: Allowing origin: ${origin}`);
      return callback(null, true);
    }

    console.log(`❌ CORS: Blocking origin: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-Request-ID',
    'X-Forwarded-For',
    'X-Forwarded-Proto',
    'X-Forwarded-Port'
  ],
  exposedHeaders: [
    'Content-Length',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset'
  ],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204
};

// Apply CORS with the above configuration
app.use(cors(corsOptions));

// ========================
// Security Headers
// ========================

// Security headers configuration
const securityHeaders = [
  // Basic security headers
  helmet.crossOriginResourcePolicy({ policy: 'same-site' }),
  helmet.crossOriginOpenerPolicy({ policy: 'same-origin-allow-popups' }),
  helmet.crossOriginEmbedderPolicy(),
  
  // Content Security Policy
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://accounts.google.com",
        "https://apis.google.com",
        "https://www.google.com",
        "https://www.gstatic.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com"
      ],
      imgSrc: [
        "'self'",
        'data:',
        'blob:',
        'https:',
        'http:'
      ],
      fontSrc: [
        "'self'",
        'data:',
        'https://fonts.gstatic.com',
        'https://fonts.googleapis.com'
      ],
      connectSrc: [
        "'self'",
        process.env.CLIENT_URL || 'https://finlogy-frontend.onrender.com',
        'https://accounts.google.com',
        'https://oauth2.googleapis.com',
        'https://www.googleapis.com',
        'wss://*.google.com',
        'ws://localhost:*',
        'ws://127.0.0.1:*'
      ],
      frameSrc: [
        "'self'",
        'https://accounts.google.com',
        'https://apis.google.com',
        'https://www.google.com'
      ],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  }),

  // Other security headers
  helmet.dnsPrefetchControl({ allow: false }),
  helmet.frameguard({ action: 'deny' }),
  helmet.hsts({
    maxAge: 63072000, // 2 years in seconds
    includeSubDomains: true,
    preload: true
  }),
  helmet.ieNoOpen(),
  helmet.noSniff(),
  helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }),
  helmet.xssFilter()
];

// Apply all security headers
app.use(securityHeaders);

// Trust first proxy (important for HTTPS in production)
app.set('trust proxy', 1);

// ========================
// Rate Limiting
// ========================
const rateLimitConfig = {
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' 
    ? parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100 
    : 1000, // More lenient in development
  standardHeaders: true,
  legacyHeaders: false,
  message: JSON.stringify({
    success: false,
    error: 'Too many requests, please try again later.'
  }),
  skip: (req) => {
    // Skip rate limiting for health checks and static files
    const skipPaths = [
      '/health',
      '/api/health',
      '/favicon.ico',
      /^\/static\//,
      /\.(js|css|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/i
    ];
    
    return skipPaths.some(path => 
      typeof path === 'string' 
        ? req.path === path 
        : path.test(req.path)
    ) || req.method === 'OPTIONS';
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later.',
      retryAfter: Math.ceil(rateLimitConfig.windowMs / 1000)
    });
  }
};

const limiter = rateLimit(rateLimitConfig);
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========================
// Session Configuration
// ========================
let sessionStore;

try {
  if (!process.env.MONGODB_URI) {
    console.warn('⚠️  MONGODB_URI is not set. Using in-memory session store (not recommended for production).');
  } else {
    sessionStore = MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions',
      autoRemove: 'interval',
      autoRemoveInterval: 10, // Check every 10 minutes
      ttl: 7 * 24 * 60 * 60, // 7 days in seconds
      touchAfter: 3 * 3600, // 3 hours in seconds
      crypto: {
        secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production'
      },
      mongoOptions: {
        retryWrites: true,
        w: 'majority',
        retryReads: true,
        readPreference: 'primary',
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 10000,
        maxPoolSize: 10,
        minPoolSize: 1,
        maxIdleTimeMS: 30000
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

// Session configuration
const sessionConfig = {
  name: 'finlogy.sid',
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: process.env.MONGODB_URI ? sessionStore : new session.MemoryStore(),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
    domain: process.env.NODE_ENV === 'production' 
      ? new URL(process.env.CLIENT_URL || 'https://finlogy-frontend.onrender.com').hostname 
      : undefined,
    // Add these for additional security
    secureProxy: process.env.NODE_ENV === 'production',
    signed: true
  },
  proxy: process.env.NODE_ENV === 'production',
  rolling: true, // Reset the cookie Max-Age on every request
  unset: 'destroy', // Delete the session when unset
  genid: (req) => {
    // Generate a secure session ID
    return require('crypto').randomBytes(16).toString('hex');
  }
};

// Apply session middleware
app.use(session(sessionConfig));

// Add request ID to each request for better logging
app.use((req, res, next) => {
  req.id = require('crypto').randomBytes(16).toString('hex');
  next();
});

// Add request logging
app.use((req, res, next) => {
  const start = Date.now();
  const { method, originalUrl, ip, id } = req;
  
  res.on('finish', () => {
    const { statusCode } = res;
    const contentLength = res.get('content-length');
    const responseTime = Date.now() - start;
    
    console.log(
      `${new Date().toISOString()} [${id}] ${method} ${originalUrl} ` +
      `${statusCode} ${contentLength || 0}b ${responseTime}ms - ${ip}`
    );
  });
  
  next();
});

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

// ========================
// Health Check Endpoint
// ========================
app.get('/api/health', async (req, res) => {
  const healthcheck = {
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    node: {
      version: process.version,
      platform: process.platform,
      arch: process.arch
    },
    system: {
      hostname: require('os').hostname(),
      loadavg: require('os').loadavg(),
      freemem: require('os').freemem(),
      totalmem: require('os').totalmem(),
      cpus: require('os').cpus().length
    },
    env: process.env.NODE_ENV || 'development',
    db: {
      status: 'unknown'
    }
  };

  // Check database connection if MongoDB URI is set
  if (process.env.MONGODB_URI) {
    try {
      const dbStatus = await mongoose.connection.db.admin().ping();
      healthcheck.db = {
        status: 'connected',
        host: mongoose.connection.host,
        name: mongoose.connection.name,
        ping: dbStatus,
        collections: (await mongoose.connection.db.listCollections().toArray()).map(c => c.name)
      };
    } catch (error) {
      healthcheck.db = {
        status: 'error',
        error: error.message
      };
      healthcheck.status = 'DOWN';
    }
  }

  const status = healthcheck.status === 'UP' ? 200 : 503;
  res.status(status).json(healthcheck);
});

// ========================
// Application Routes
// ========================
app.use('/api/auth', authRoutes);
app.use('/api/expenses', expenseRoutes);
app.use('/api/income', incomeRoutes);
app.use('/api/budgets', budgetRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/feedback', feedbackRoutes);

// ========================
// Error Handling Middleware
// ========================

// 404 Handler
app.use((req, res, next) => {
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
