const express = require('express');
const router = express.Router();
const notificationController = require('../controllers/notification.controller');
const { authenticateApiKey, notificationLimiter } = require('../middleware/auth.middleware');
const { validate, validationRules } = require('../middleware/validation.middleware');

// All routes require authentication
router.use(authenticateApiKey);

// Save/Update FCM Token
router.post('/save-token', 
  validationRules.saveToken,
  validate,
  notificationController.saveToken
);

// Send notification with token validation
router.post('/send-notification',
  notificationLimiter,
  validationRules.sendNotification,
  validate,
  notificationController.sendNotification
);

// Send notification to multiple devices
router.post('/send-multicast',
  notificationLimiter,
  validationRules.sendMulticast,
  validate,
  notificationController.sendMulticast
);

// Send notification to a topic
router.post('/send-topic',
  notificationLimiter,
  validationRules.sendTopic,
  validate,
  notificationController.sendToTopic
);

// Subscribe device(s) to topic
router.post('/subscribe-topic',
  validationRules.subscribeTopic,
  validate,
  notificationController.subscribeTopic
);

// Unsubscribe device(s) from topic
router.post('/unsubscribe-topic',
  validationRules.subscribeTopic,
  validate,
  notificationController.unsubscribeTopic
);

// Send data-only message
router.post('/send-data',
  notificationLimiter,
  validationRules.sendData,
  validate,
  notificationController.sendDataMessage
);

// Delete/Invalidate Token
router.post('/delete-token',
  validationRules.deleteToken,
  validate,
  notificationController.deleteToken
);

// Send to user by userId (no need to know token)
router.post('/notify-user',
  notificationLimiter,
  validationRules.notifyUser,
  validate,
  notificationController.notifyUser
);

module.exports = router;
