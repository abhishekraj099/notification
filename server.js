const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// ✅ USE SHARED FIREBASE CONFIG
const { admin, database } = require('./config/firebase');

const app = express();

// ============================================================================
// VERCEL / PROXY CONFIGURATION
// ============================================================================

app.set('trust proxy', 1);
app.disable('x-powered-by');

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').filter(o => o.trim()) || [];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.length > 0 && process.env.NODE_ENV === 'production') {
      if (allowedOrigins.indexOf(origin) === -1) {
        return callback(new Error('CORS policy violation'), false);
      }
    }
    
    callback(null, true);
  },
  credentials: true
}));

// Rate limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { 
    success: false, 
    error: 'Too many requests from this IP, please try again later' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: true,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown'
});

const notificationLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { 
    success: false, 
    error: 'Notification rate limit exceeded. Maximum 20 per minute.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: true,
  keyGenerator: (req) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey) return `apikey_${apiKey.substring(0, 10)}`;
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});

app.use('/api/', globalLimiter);

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

const authenticate = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const validApiKeys = process.env.API_KEYS?.split(',').filter(k => k.trim()) || [];
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required: Missing X-API-Key header'
    });
  }
  
  if (!validApiKeys.includes(apiKey)) {
    console.warn(`⚠️  Invalid API key attempt from IP: ${req.ip}`);
    return res.status(401).json({
      success: false,
      error: 'Invalid API key'
    });
  }
  
  console.log(`✅ Authenticated request from IP: ${req.ip} to ${req.path}`);
  next();
};

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/', async (req, res) => {
  const health = {
    service: 'Firebase Notification API',
    status: 'active',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    checks: {}
  };
  
  try {
    await database.ref('.info/connected').once('value');
    health.checks.database = 'connected';
  } catch (error) {
    health.checks.database = 'disconnected';
    health.status = 'degraded';
  }
  
  try {
    const messaging = admin.messaging();
    health.checks.fcm = messaging ? 'available' : 'unavailable';
  } catch (error) {
    health.checks.fcm = 'unavailable';
    health.status = 'degraded';
  }
  
  const statusCode = health.status === 'active' ? 200 : 503;
  res.status(statusCode).json(health);
});

// ============================================================================
// TOKEN MANAGEMENT ENDPOINTS
// ============================================================================

app.post('/api/save-token',
  authenticate,
  notificationLimiter,
  [
    body('userId')
      .isString()
      .trim()
      .isLength({ min: 1, max: 128 })
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid userId format'),
    body('token')
      .isString()
      .trim()
      .isLength({ min: 100, max: 300 })
      .withMessage('Invalid FCM token format'),
    body('deviceInfo')
      .optional()
      .isObject()
      .withMessage('deviceInfo must be an object'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array().map(err => ({
          field: err.path,
          message: err.msg
        }))
      });
    }
    
    try {
      const { userId, token, deviceInfo } = req.body;

      const tokenData = {
        token: token,
        userId: userId,
        deviceInfo: deviceInfo || {},
        createdAt: admin.database.ServerValue.TIMESTAMP,
        updatedAt: admin.database.ServerValue.TIMESTAMP,
        isActive: true
      };

      await database.ref(`fcmTokens/${userId}`).set(tokenData);

      console.log(`✅ Token saved for user: ${userId}`);
      
      res.status(200).json({
        success: true,
        message: 'Token saved successfully'
      });
    } catch (error) {
      console.error('❌ Error saving token:', error.message);
      res.status(500).json({
        success: false,
        error: 'Failed to save token. Please try again.'
      });
    }
  }
);

app.post('/api/delete-token',
  authenticate,
  [
    body('userId')
      .isString()
      .trim()
      .notEmpty()
      .withMessage('userId is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    
    try {
      const { userId } = req.body;

      await database.ref(`fcmTokens/${userId}`).update({ 
        isActive: false,
        deletedAt: admin.database.ServerValue.TIMESTAMP
      });

      console.log(`✅ Token invalidated for user: ${userId}`);

      res.status(200).json({
        success: true,
        message: 'Token invalidated successfully'
      });
    } catch (error) {
      console.error('❌ Error deleting token:', error.message);
      res.status(500).json({
        success: false,
        error: 'Failed to delete token'
      });
    }
  }
);

// ============================================================================
// NOTIFICATION SENDING ENDPOINTS
// ============================================================================

app.post('/api/notify-user',
  authenticate,
  notificationLimiter,
  [
    body('userId')
      .isString()
      .trim()
      .notEmpty()
      .withMessage('userId is required'),
    body('title')
      .isString()
      .trim()
      .isLength({ min: 1, max: 100 })
      .escape()
      .withMessage('Title must be 1-100 characters'),
    body('body')
      .isString()
      .trim()
      .isLength({ min: 1, max: 500 })
      .escape()
      .withMessage('Body must be 1-500 characters'),
    body('data')
      .optional()
      .isObject(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    
    try {
      const { userId, title, body, data } = req.body;

      const snapshot = await database.ref(`fcmTokens/${userId}`).once('value');
      const tokenData = snapshot.val();

      if (!tokenData || !tokenData.isActive) {
        return res.status(404).json({
          success: false,
          error: 'No active token found for this user'
        });
      }

      const message = {
        notification: {
          title: title,
          body: body
        },
        data: data || {},
        android: {
          priority: 'high',
          notification: {
            sound: 'default'
          }
        },
        token: tokenData.token
      };

      const response = await admin.messaging().send(message);

      console.log(`✅ Notification sent to user: ${userId}`, response);

      res.status(200).json({
        success: true,
        message: 'Notification sent successfully',
        messageId: response
      });
    } catch (error) {
      console.error('❌ Error notifying user:', error.message);
      
      if (error.code === 'messaging/invalid-registration-token' ||
          error.code === 'messaging/registration-token-not-registered') {
        await database.ref(`fcmTokens/${req.body.userId}`).update({ isActive: false });
      }
      
      res.status(500).json({
        success: false,
        error: 'Failed to send notification'
      });
    }
  }
);

app.post('/api/send-multicast',
  authenticate,
  notificationLimiter,
  [
    body('tokens')
      .isArray({ min: 1, max: 500 })
      .withMessage('tokens must be an array with 1-500 elements'),
    body('title').isString().trim().isLength({ min: 1, max: 100 }).escape(),
    body('body').isString().trim().isLength({ min: 1, max: 500 }).escape(),
    body('data').optional().isObject(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    
    try {
      const { tokens, title, body, data } = req.body;

      const message = {
        notification: { title, body },
        data: data || {},
        android: {
          priority: 'high',
          notification: { sound: 'default' }
        },
        tokens: tokens
      };

      const response = await admin.messaging().sendEachForMulticast(message);
      
      console.log(`✅ Multicast sent: ${response.successCount}/${tokens.length} successful`);
      
      res.status(200).json({
        success: true,
        successCount: response.successCount,
        failureCount: response.failureCount
      });
    } catch (error) {
      console.error('❌ Error sending multicast:', error.message);
      res.status(500).json({
        success: false,
        error: 'Failed to send multicast notification'
      });
    }
  }
);

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.message);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.path
  });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 Firebase Notification API - Production Ready');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security: Enabled`);
  console.log(`🔑 Authentication: ${process.env.API_KEYS ? 'Configured ✅' : 'NOT CONFIGURED ⚠️'}`);
  console.log('='.repeat(60) + '\n');
});

module.exports = app;
