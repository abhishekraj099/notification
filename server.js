const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
require('dotenv').config();


// ============================================================================
// FIREBASE ADMIN INITIALIZATION - SECURE METHOD
// ============================================================================


let serviceAccount;


if (process.env.SERVICE_ACCOUNT_BASE64) {
  // For Render deployment - using base64 encoded service account
  const decoded = Buffer.from(process.env.SERVICE_ACCOUNT_BASE64, 'base64').toString();
  serviceAccount = JSON.parse(decoded);
} else {
  // Use individual environment variables (NO FILE LOADING)
  serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
  };
  
  // Validate all credentials are present
  if (!serviceAccount.projectId || !serviceAccount.clientEmail || !serviceAccount.privateKey) {
    console.error('❌ Missing Firebase credentials in environment variables');
    console.error('Required: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY');
    process.exit(1);
  }
}


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://notifaction-f0929-default-rtdb.firebaseio.com"
});


console.log('✅ Firebase Admin initialized securely');


const app = express();
const db = admin.database();

// ============================================================================
// VERCEL / PROXY CONFIGURATION (FIX FOR RATE LIMITING)
// ============================================================================

// ✅ Trust Vercel's proxy - CRITICAL for rate limiting and IP detection
app.set('trust proxy', 1);
app.disable('x-powered-by');


// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================


// Security headers
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


// Request size limits (prevent DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// CORS - restrict to your domains
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').filter(o => o.trim()) || [];
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, curl)
    if (!origin) return callback(null, true);
    
    // In production, only allow whitelisted origins
    if (allowedOrigins.length > 0 && process.env.NODE_ENV === 'production') {
      if (allowedOrigins.indexOf(origin) === -1) {
        return callback(new Error('CORS policy violation'), false);
      }
    }
    
    callback(null, true);
  },
  credentials: true
}));


// ✅ UPDATED: Global rate limiter with Vercel-compatible configuration
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  message: { 
    success: false, 
    error: 'Too many requests from this IP, please try again later' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  // ✅ Skip failed requests (don't count towards limit)
  skipFailedRequests: true,
  // ✅ Simple key generator for Vercel
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});


// ✅ UPDATED: Notification rate limiter with Vercel-compatible configuration
const notificationLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 notifications per minute (increased for testing)
  message: { 
    success: false, 
    error: 'Notification rate limit exceeded. Maximum 20 per minute.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: true,
  keyGenerator: (req) => {
    // Rate limit by API key or IP
    const apiKey = req.headers['x-api-key'];
    if (apiKey) return `apikey_${apiKey.substring(0, 10)}`;
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});


// Apply global rate limiting to all API routes
app.use('/api/', globalLimiter);


// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================


// Simple API Key Authentication
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
    console.warn(`⚠️  Invalid API key attempt: ${apiKey.substring(0, 8)}... from IP: ${req.ip} at ${new Date().toISOString()}`);
    return res.status(401).json({
      success: false,
      error: 'Invalid API key'
    });
  }
  
  // Log successful authentication
  console.log(`✅ Authenticated request from IP: ${req.ip} to ${req.path}`);
  next();
};


// Optional: Firebase Auth middleware (for user-specific operations)
const authenticateFirebaseUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Missing or invalid authorization header. Expected: Bearer <token>'
      });
    }
    
    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      emailVerified: decodedToken.email_verified
    };
    
    console.log(`✅ Firebase user authenticated: ${req.user.uid}`);
    next();
  } catch (error) {
    console.error('❌ Firebase auth error:', error.code);
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired authentication token'
    });
  }
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
  
  // Test Firebase Realtime Database connection
  try {
    await db.ref('.info/connected').once('value');
    health.checks.database = 'connected';
  } catch (error) {
    health.checks.database = 'disconnected';
    health.status = 'degraded';
  }
  
  // Test FCM availability - simplified check
  try {
    const messaging = admin.messaging();
    health.checks.fcm = messaging ? 'available' : 'unavailable';
  } catch (error) {
    console.log('🔍 FCM Health Check Error:', {
      code: error.code,
      message: error.message
    });
    health.checks.fcm = 'unavailable';
    health.status = 'degraded';
  }
  
  const statusCode = health.status === 'active' ? 200 : 503;
  res.status(statusCode).json(health);
});


// ============================================================================
// TOKEN MANAGEMENT ENDPOINTS
// ============================================================================


// Save/Update FCM Token
app.post('/api/save-token',
  authenticate,
  notificationLimiter,
  [
    body('userId')
      .isString()
      .trim()
      .isLength({ min: 1, max: 128 })
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid userId format. Must be alphanumeric with _ or -'),
    body('token')
      .isString()
      .trim()
      .isLength({ min: 100, max: 300 })
      .matches(/^[a-zA-Z0-9_:-]+$/)
      .withMessage('Invalid FCM token format'),
    body('deviceInfo')
      .optional()
      .isObject()
      .withMessage('deviceInfo must be an object'),
  ],
  async (req, res) => {
    // Validate input
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

      // ✅ Optional: Verify token validity with FCM dry run (can be disabled for faster saves)
      // Uncomment if you want strict validation
      /*
      try {
        await admin.messaging().send({
          token: token,
          data: { test: 'validation' }
        }, true); // dry_run = true
      } catch (validationError) {
        if (validationError.code === 'messaging/invalid-registration-token' ||
            validationError.code === 'messaging/registration-token-not-registered') {
          return res.status(400).json({
            success: false,
            error: 'Invalid FCM token provided. Please generate a new token.'
          });
        }
      }
      */

      const tokenData = {
        token: token,
        userId: userId,
        deviceInfo: deviceInfo || {},
        createdAt: admin.database.ServerValue.TIMESTAMP,
        updatedAt: admin.database.ServerValue.TIMESTAMP,
        isActive: true
      };

      await db.ref(`fcmTokens/${userId}`).set(tokenData);

      console.log(`✅ Token saved for user: ${userId}`);
      
      res.status(200).json({
        success: true,
        message: 'Token saved successfully'
      });
    } catch (error) {
      console.error('❌ Error saving token:', {
        userId: req.body.userId,
        error: error.code || error.message,
        timestamp: new Date().toISOString()
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to save token. Please try again.'
      });
    }
  }
);


// Delete/Invalidate Token
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

      await db.ref(`fcmTokens/${userId}`).update({ 
        isActive: false,
        deletedAt: admin.database.ServerValue.TIMESTAMP
      });

      console.log(`✅ Token invalidated for user: ${userId}`);

      res.status(200).json({
        success: true,
        message: 'Token invalidated successfully'
      });
    } catch (error) {
      console.error('❌ Error deleting token:', error.code);
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


// Send notification with token or userId
app.post('/api/send-notification',
  authenticate,
  notificationLimiter,
  [
    body('userId').optional().isString().trim(),
    body('token').optional().isString().trim().isLength({ min: 100, max: 300 }),
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
      .isObject()
      .custom((value) => {
        // FCM requires all data values to be strings
        const allStrings = Object.values(value).every(v => typeof v === 'string');
        if (!allStrings) {
          throw new Error('All data values must be strings');
        }
        return true;
      }),
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
      const { userId, token, title, body, data } = req.body;

      let fcmToken = token;
      
      // If userId provided, fetch token from database
      if (userId && !token) {
        const snapshot = await db.ref(`fcmTokens/${userId}`).once('value');
        const tokenData = snapshot.val();
        
        if (!tokenData || !tokenData.isActive) {
          return res.status(404).json({
            success: false,
            error: 'No active token found for this user'
          });
        }
        
        fcmToken = tokenData.token;
      }

      if (!fcmToken) {
        return res.status(400).json({
          success: false,
          error: 'Either userId or token must be provided'
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
            sound: 'default',
            clickAction: 'FLUTTER_NOTIFICATION_CLICK'
          }
        },
        token: fcmToken
      };

      const response = await admin.messaging().send(message);
      
      console.log('✅ Notification sent:', {
        messageId: response,
        userId: userId || 'N/A',
        title: title.substring(0, 30),
        timestamp: new Date().toISOString()
      });
      
      res.status(200).json({
        success: true,
        message: 'Notification sent successfully',
        messageId: response
      });
    } catch (error) {
      console.error('❌ Notification error:', {
        code: error.code,
        message: error.message,
        userId: req.body.userId,
        timestamp: new Date().toISOString()
      });
      
      // Handle invalid token
      if (error.code === 'messaging/invalid-registration-token' ||
          error.code === 'messaging/registration-token-not-registered') {
        
        const { userId } = req.body;
        if (userId) {
          await db.ref(`fcmTokens/${userId}`).update({ isActive: false });
          console.log(`⚠️  Marked token as inactive for user: ${userId}`);
        }
        
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired FCM token'
        });
      }
      
      // ✅ Handle credential mismatch
      if (error.code === 'messaging/mismatched-credential') {
        return res.status(500).json({
          success: false,
          error: 'Firebase credential mismatch. Check server configuration.'
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'Failed to send notification'
      });
    }
  }
);


// Send notification to user by userId (simplified endpoint)
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
      .isObject()
      .custom((value) => {
        const allStrings = Object.values(value).every(v => typeof v === 'string');
        if (!allStrings) {
          throw new Error('All data values must be strings');
        }
        return true;
      }),
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

      const snapshot = await db.ref(`fcmTokens/${userId}`).once('value');
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

      console.log(`✅ Notification sent to user: ${userId}`, {
        messageId: response,
        title: title.substring(0, 30)
      });

      res.status(200).json({
        success: true,
        message: 'Notification sent successfully',
        messageId: response
      });
    } catch (error) {
      console.error('❌ Error notifying user:', {
        code: error.code,
        message: error.message,
        userId: req.body.userId
      });
      
      if (error.code === 'messaging/invalid-registration-token' ||
          error.code === 'messaging/registration-token-not-registered') {
        await db.ref(`fcmTokens/${req.body.userId}`).update({ isActive: false });
      }
      
      // ✅ Handle credential mismatch
      if (error.code === 'messaging/mismatched-credential') {
        return res.status(500).json({
          success: false,
          error: 'Firebase credential mismatch. Verify Firebase project configuration.'
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'Failed to send notification'
      });
    }
  }
);


// Send notification to multiple devices
app.post('/api/send-multicast',
  authenticate,
  notificationLimiter,
  [
    body('tokens')
      .isArray({ min: 1, max: 500 })
      .withMessage('tokens must be an array with 1-500 elements'),
    body('tokens.*')
      .isString()
      .trim()
      .isLength({ min: 100, max: 300 })
      .withMessage('Invalid token format'),
    body('title')
      .isString()
      .trim()
      .isLength({ min: 1, max: 100 })
      .escape(),
    body('body')
      .isString()
      .trim()
      .isLength({ min: 1, max: 500 })
      .escape(),
    body('data')
      .optional()
      .isObject()
      .custom((value) => {
        return Object.values(value).every(v => typeof v === 'string');
      }),
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
        tokens: tokens
      };

      const response = await admin.messaging().sendEachForMulticast(message);
      
      console.log(`✅ Multicast sent: ${response.successCount}/${tokens.length} successful`);
      
      res.status(200).json({
        success: true,
        successCount: response.successCount,
        failureCount: response.failureCount,
        results: response.responses.map((resp, idx) => ({
          token: tokens[idx].substring(0, 20) + '...',
          success: resp.success,
          messageId: resp.messageId,
          error: resp.error ? resp.error.code : null
        }))
      });
    } catch (error) {
      console.error('❌ Error sending multicast:', error.code);
      res.status(500).json({
        success: false,
        error: 'Failed to send multicast notification'
      });
    }
  }
);


// Send notification to a topic
app.post('/api/send-topic',
  authenticate,
  notificationLimiter,
  [
    body('topic')
      .isString()
      .trim()
      .matches(/^[a-zA-Z0-9-_.~%]+$/)
      .withMessage('Invalid topic name format'),
    body('title')
      .isString()
      .trim()
      .isLength({ min: 1, max: 100 })
      .escape(),
    body('body')
      .isString()
      .trim()
      .isLength({ min: 1, max: 500 })
      .escape(),
    body('data')
      .optional()
      .isObject()
      .custom((value) => {
        return Object.values(value).every(v => typeof v === 'string');
      }),
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
      const { topic, title, body, data } = req.body;

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
        topic: topic
      };

      const response = await admin.messaging().send(message);
      
      console.log(`✅ Topic notification sent to: ${topic}`);
      
      res.status(200).json({
        success: true,
        message: `Topic notification sent to: ${topic}`,
        messageId: response
      });
    } catch (error) {
      console.error('❌ Error sending topic notification:', error.code);
      res.status(500).json({
        success: false,
        error: 'Failed to send topic notification'
      });
    }
  }
);


// ============================================================================
// TOPIC SUBSCRIPTION ENDPOINTS
// ============================================================================


// Subscribe device(s) to topic
app.post('/api/subscribe-topic',
  authenticate,
  [
    body('tokens')
      .custom((value) => {
        if (typeof value === 'string') return true;
        if (Array.isArray(value) && value.length > 0) return true;
        throw new Error('tokens must be a string or non-empty array');
      }),
    body('topic')
      .isString()
      .trim()
      .matches(/^[a-zA-Z0-9-_.~%]+$/)
      .withMessage('Invalid topic name'),
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
      const { tokens, topic } = req.body;

      const tokenArray = Array.isArray(tokens) ? tokens : [tokens];
      const response = await admin.messaging().subscribeToTopic(tokenArray, topic);
      
      console.log(`✅ Subscribed ${response.successCount} devices to topic: ${topic}`);
      
      res.status(200).json({
        success: true,
        message: `Subscribed to topic: ${topic}`,
        successCount: response.successCount,
        failureCount: response.failureCount,
        errors: response.errors
      });
    } catch (error) {
      console.error('❌ Error subscribing to topic:', error.code);
      res.status(500).json({
        success: false,
        error: 'Failed to subscribe to topic'
      });
    }
  }
);


// Unsubscribe device(s) from topic
app.post('/api/unsubscribe-topic',
  authenticate,
  [
    body('tokens')
      .custom((value) => {
        if (typeof value === 'string') return true;
        if (Array.isArray(value) && value.length > 0) return true;
        throw new Error('tokens must be a string or non-empty array');
      }),
    body('topic')
      .isString()
      .trim()
      .matches(/^[a-zA-Z0-9-_.~%]+$/)
      .withMessage('Invalid topic name'),
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
      const { tokens, topic } = req.body;

      const tokenArray = Array.isArray(tokens) ? tokens : [tokens];
      const response = await admin.messaging().unsubscribeFromTopic(tokenArray, topic);
      
      console.log(`✅ Unsubscribed ${response.successCount} devices from topic: ${topic}`);
      
      res.status(200).json({
        success: true,
        message: `Unsubscribed from topic: ${topic}`,
        successCount: response.successCount,
        failureCount: response.failureCount,
        errors: response.errors
      });
    } catch (error) {
      console.error('❌ Error unsubscribing from topic:', error.code);
      res.status(500).json({
        success: false,
        error: 'Failed to unsubscribe from topic'
      });
    }
  }
);


// ============================================================================
// DATA MESSAGE ENDPOINT
// ============================================================================


// Send data-only message (no notification UI)
app.post('/api/send-data',
  authenticate,
  notificationLimiter,
  [
    body('token')
      .isString()
      .trim()
      .isLength({ min: 100, max: 300 })
      .withMessage('Valid FCM token required'),
    body('data')
      .isObject()
      .notEmpty()
      .withMessage('data object is required')
      .custom((value) => {
        return Object.values(value).every(v => typeof v === 'string');
      }),
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
      const { token, data } = req.body;

      const message = {
        data: data,
        android: {
          priority: 'high'
        },
        token: token
      };

      const response = await admin.messaging().send(message);
      
      console.log('✅ Data message sent:', response);
      
      res.status(200).json({
        success: true,
        message: 'Data message sent successfully',
        messageId: response
      });
    } catch (error) {
      console.error('❌ Error sending data message:', error.code);
      res.status(500).json({
        success: false,
        error: 'Failed to send data message'
      });
    }
  }
);


// ============================================================================
// ERROR HANDLING MIDDLEWARE
// ============================================================================


// Global error handler
app.use((err, req, res, next) => {
  // Log full error details server-side
  console.error('❌ Unhandled error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  // Send generic error to client (don't leak system info)
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});


// 404 handler
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
  console.log('🚀 Firebase Notification API - SECURE VERSION');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security: Enabled (Helmet, Rate Limiting, Auth)`);
  console.log(`🔑 Authentication: ${process.env.API_KEYS ? 'Configured ✅' : 'NOT CONFIGURED ⚠️'}`);
  console.log(`🌍 CORS: ${allowedOrigins.length > 0 ? `Restricted to ${allowedOrigins.length} origin(s)` : 'Open (Dev Mode)'}`);
  console.log(`🔧 Trust Proxy: Enabled (Vercel compatible)`);
  console.log('='.repeat(60) + '\n');
  
  // Warn if running without proper security
  if (!process.env.API_KEYS) {
    console.warn('⚠️  WARNING: API_KEYS not configured! Authentication disabled!');
    console.warn('⚠️  Set API_KEYS environment variable before production deployment!\n');
  }
  
  if (process.env.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    console.warn('⚠️  WARNING: ALLOWED_ORIGINS not configured in production!');
    console.warn('⚠️  CORS is open to all origins!\n');
  }
});
