const { body, validationResult } = require('express-validator');

// Validation helper - checks for validation errors
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// Input sanitization
const sanitizeString = (str, maxLength = 500) => {
  if (!str) return '';
  return str
    .replace(/[<>]/g, '') // Remove potential HTML/XSS
    .trim()
    .substring(0, maxLength);
};

// Validation rules for different endpoints
const validationRules = {
  saveToken: [
    body('userId').isString().trim().isLength({ min: 1, max: 128 }).matches(/^[a-zA-Z0-9_-]+$/),
    body('token').isString().trim().isLength({ min: 10, max: 1024 }),
    body('deviceInfo').optional().isObject(),
  ],

  sendNotification: [
    body('userId').optional().isString().trim().isLength({ max: 128 }),
    body('token').optional().isString().trim().isLength({ max: 1024 }),
    body('title').isString().trim().isLength({ min: 1, max: 100 }),
    body('body').isString().trim().isLength({ min: 1, max: 500 }),
    body('data').optional().isObject(),
  ],

  sendMulticast: [
    body('tokens').isArray({ min: 1, max: 500 }),
    body('title').isString().trim().isLength({ min: 1, max: 100 }),
    body('body').isString().trim().isLength({ min: 1, max: 500 }),
    body('data').optional().isObject(),
  ],

  sendTopic: [
    body('topic').isString().trim().isLength({ min: 1, max: 100 }).matches(/^[a-zA-Z0-9_-]+$/),
    body('title').isString().trim().isLength({ min: 1, max: 100 }),
    body('body').isString().trim().isLength({ min: 1, max: 500 }),
    body('data').optional().isObject(),
  ],

  subscribeTopic: [
    body('tokens').custom((value) => {
      const arr = Array.isArray(value) ? value : [value];
      return arr.length > 0 && arr.length <= 100;
    }),
    body('topic').isString().trim().isLength({ min: 1, max: 100 }).matches(/^[a-zA-Z0-9_-]+$/),
  ],

  sendData: [
    body('token').isString().trim().isLength({ min: 10, max: 1024 }),
    body('data').isObject(),
  ],

  deleteToken: [
    body('userId').isString().trim().isLength({ min: 1, max: 128 }).matches(/^[a-zA-Z0-9_-]+$/),
  ],

  notifyUser: [
    body('userId').isString().trim().isLength({ min: 1, max: 128 }).matches(/^[a-zA-Z0-9_-]+$/),
    body('title').isString().trim().isLength({ min: 1, max: 100 }),
    body('body').isString().trim().isLength({ min: 1, max: 500 }),
    body('data').optional().isObject(),
  ],
};

module.exports = {
  validate,
  sanitizeString,
  validationRules
};
