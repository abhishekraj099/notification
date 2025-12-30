const rateLimit = require('express-rate-limit');

// Load API keys from environment
const VALID_API_KEYS = new Set(
  (process.env.API_KEYS || '').split(',').filter(key => key.length > 0)
);

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required. Include X-API-Key header.'
    });
  }
  
  if (!VALID_API_KEYS.has(apiKey)) {
    console.warn(`[SECURITY] Invalid API key attempt from IP: ${req.ip} at ${new Date().toISOString()}`);
    return res.status(403).json({
      success: false,
      error: 'Invalid API key'
    });
  }
  
  next();
};

// Rate limiting configurations
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const notificationLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 notifications per minute per IP
  message: {
    success: false,
    error: 'Notification rate limit exceeded. Maximum 10 notifications per minute.'
  }
});

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    }));
  });
  next();
};

module.exports = {
  authenticateApiKey,
  apiLimiter,
  notificationLimiter,
  requestLogger,
  VALID_API_KEYS
};
