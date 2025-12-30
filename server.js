const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Import configuration and middleware
const { admin } = require('./config/firebase');
const { apiLimiter, requestLogger, VALID_API_KEYS } = require('./middleware/auth.middleware');

// Import routes
const notificationRoutes = require('./routes/notification.routes');

const app = express();

// ✅ CRITICAL FIX: Trust proxy for Render deployment
// This fixes rate limiting and IP detection behind Render's proxy
app.set('trust proxy', 1);

// ========================================
// SECURITY CONFIGURATION
// ========================================

// Security: Request size limit to prevent memory exhaustion
app.use(express.json({ limit: '10kb' }));

// Security: CORS configuration for mobile apps
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, native apps)
    if (!origin) {
      return callback(null, true);
    }
    
    // Allow all origins if ALLOWED_ORIGINS is * or empty
    if (process.env.ALLOWED_ORIGINS === '*' || !process.env.ALLOWED_ORIGINS) {
      return callback(null, true);
    }
    
    // Check if origin is in allowed list
    const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key', 'Authorization', 'X-User-Id'],
  credentials: true,
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200 // For legacy browser support
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Security: Request logging for monitoring
app.use(requestLogger);

// Apply rate limiting to all API routes
app.use('/api/', apiLimiter);

// ========================================
// PUBLIC ENDPOINTS (No Auth Required)
// ========================================

// Health check - Public endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Firebase Notification API is running!',
    status: 'active',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '2.0.0',
    endpoints: {
      health: '/health',
      api: '/api/*',
      docs: 'See README.md for API documentation'
    }
  });
});

// Detailed health check with dependencies
app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    checks: {
      firebase: 'unknown',
      database: 'unknown'
    }
  };

  try {
    const { db } = require('./config/firebase');
    await db.ref('.info/connected').once('value');
    health.checks.database = 'healthy';
  } catch (error) {
    health.checks.database = 'unhealthy';
    health.status = 'degraded';
    console.error('Database health check failed:', error.message);
  }

  health.checks.firebase = admin.apps.length > 0 ? 'healthy' : 'unhealthy';
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

// API documentation endpoint
app.get('/api', (req, res) => {
  res.json({
    message: 'Firebase Cloud Messaging API',
    version: '2.0.0',
    authentication: 'Required: X-API-Key header',
    endpoints: {
      'POST /api/save-token': 'Save FCM token for a user',
      'POST /api/send-notification': 'Send notification to single device',
      'POST /api/send-multicast': 'Send notification to multiple devices',
      'POST /api/send-topic': 'Send notification to topic subscribers',
      'POST /api/subscribe-topic': 'Subscribe devices to a topic',
      'POST /api/unsubscribe-topic': 'Unsubscribe devices from a topic',
      'POST /api/send-data': 'Send data-only message',
      'POST /api/delete-token': 'Invalidate user token',
      'POST /api/notify-user': 'Send notification to user by userId'
    },
    documentation: 'See README.md for detailed API documentation'
  });
});

// ========================================
// PROTECTED API ROUTES
// ========================================

app.use('/api', notificationRoutes);

// ========================================
// ERROR HANDLING
// ========================================

// CORS error handler
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: 'CORS policy violation',
      message: 'Origin not allowed'
    });
  }
  next(err);
});

// General error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  });
  
  res.status(err.status || 500).json({
    success: false,
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An error occurred'
  });
});

// 404 handler - Must be last
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.path,
    method: req.method,
    suggestion: 'Check API documentation at GET /api'
  });
});

// ========================================
// SERVER STARTUP
// ========================================

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 FIREBASE NOTIFICATION API SERVER');
  console.log('='.repeat(60));
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}/`);
  console.log(`📊 Health: http://localhost:${PORT}/health`);
  console.log(`📚 API Docs: http://localhost:${PORT}/api`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`⏰ Started: ${new Date().toLocaleString()}`);
  console.log('\n' + '-'.repeat(60));
  console.log('🔒 SECURITY STATUS');
  console.log('-'.repeat(60));
  console.log(`✅ Authentication: ${VALID_API_KEYS.size > 0 ? 'ENABLED' : '⚠️  DISABLED (WARNING!)'}`);
  console.log(`✅ Rate Limiting: ENABLED`);
  console.log(`✅ Input Validation: ENABLED`);
  
  if (process.env.ALLOWED_ORIGINS === '*' || !process.env.ALLOWED_ORIGINS) {
    console.log(`✅ CORS: OPEN (Mobile Apps Supported)`);
  } else {
    console.log(`✅ CORS: RESTRICTED to ${process.env.ALLOWED_ORIGINS}`);
  }
  
  console.log('='.repeat(60) + '\n');
  console.log('📱 Ready to send Firebase notifications!\n');
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use. Try a different port.`);
  } else {
    console.error('❌ Server error:', error);
  }
  process.exit(1);
});

// Graceful shutdown handler
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received, closing server gracefully...`);
  
  // Stop accepting new connections
  server.close(async () => {
    console.log('✅ HTTP server closed');
    
    try {
      // Clean up Firebase connection
      await admin.app().delete();
      console.log('✅ Firebase Admin cleaned up');
    } catch (error) {
      console.error('❌ Error during Firebase cleanup:', error.message);
    }
    
    console.log('✅ Server shut down successfully');
    process.exit(0);
  });
  
  // Force close after 10 seconds if graceful shutdown fails
  setTimeout(() => {
    console.error('⚠️  Graceful shutdown timeout, forcing exit...');
    process.exit(1);
  }, 10000);
};

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});
