const { admin, db } = require('../config/firebase');
const { sanitizeString } = require('../middleware/validation.middleware');

// Save/Update FCM Token
exports.saveToken = async (req, res) => {
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

    await db.ref(`fcmTokens/${userId}`).set(tokenData);

    res.status(200).json({
      success: true,
      message: 'Token saved successfully'
    });
  } catch (error) {
    console.error('Error saving token:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Send notification to single device
exports.sendNotification = async (req, res) => {
  try {
    const { userId, token, data } = req.body;
    
    // Sanitize notification content
    const title = sanitizeString(req.body.title, 100);
    const body = sanitizeString(req.body.body, 500);

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
        error: 'Token or userId required'
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
          channelId: 'default_channel'
        }
      },
      token: fcmToken
    };

    const response = await admin.messaging().send(message);
    
    res.status(200).json({
      success: true,
      message: 'Notification sent successfully',
      messageId: response
    });
  } catch (error) {
    console.error('Error sending notification:', error);
    
    // Handle invalid token
    if (error.code === 'messaging/invalid-registration-token' ||
        error.code === 'messaging/registration-token-not-registered') {
      
      const { userId } = req.body;
      if (userId) {
        await db.ref(`fcmTokens/${userId}`).update({ isActive: false });
        console.log(`Marked token as inactive for user: ${userId}`);
      }
      
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired FCM token. Token marked as inactive.',
        code: error.code
      });
    }
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Send notification to multiple devices
exports.sendMulticast = async (req, res) => {
  try {
    const { tokens, data } = req.body;
    
    const title = sanitizeString(req.body.title, 100);
    const body = sanitizeString(req.body.body, 500);

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
          channelId: 'default_channel'
        }
      },
      tokens: tokens
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    
    res.status(200).json({
      success: true,
      successCount: response.successCount,
      failureCount: response.failureCount,
      results: response.responses.map((resp, idx) => ({
        token: tokens[idx],
        success: resp.success,
        messageId: resp.messageId,
        error: resp.error ? resp.error.message : null
      }))
    });
  } catch (error) {
    console.error('Error sending multicast:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Send notification to a topic
exports.sendToTopic = async (req, res) => {
  try {
    const { topic, data } = req.body;
    
    const title = sanitizeString(req.body.title, 100);
    const body = sanitizeString(req.body.body, 500);

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
          channelId: 'default_channel'
        }
      },
      topic: topic
    };

    const response = await admin.messaging().send(message);
    
    res.status(200).json({
      success: true,
      message: `Topic notification sent to: ${topic}`,
      messageId: response
    });
  } catch (error) {
    console.error('Error sending topic notification:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Subscribe device(s) to topic
exports.subscribeTopic = async (req, res) => {
  try {
    const { tokens, topic } = req.body;

    const tokenArray = Array.isArray(tokens) ? tokens : [tokens];
    const response = await admin.messaging().subscribeToTopic(tokenArray, topic);
    
    res.status(200).json({
      success: true,
      message: `Subscribed to topic: ${topic}`,
      successCount: response.successCount,
      failureCount: response.failureCount,
      errors: response.errors
    });
  } catch (error) {
    console.error('Error subscribing to topic:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Unsubscribe device(s) from topic
exports.unsubscribeTopic = async (req, res) => {
  try {
    const { tokens, topic } = req.body;

    const tokenArray = Array.isArray(tokens) ? tokens : [tokens];
    const response = await admin.messaging().unsubscribeFromTopic(tokenArray, topic);
    
    res.status(200).json({
      success: true,
      message: `Unsubscribed from topic: ${topic}`,
      successCount: response.successCount,
      failureCount: response.failureCount,
      errors: response.errors
    });
  } catch (error) {
    console.error('Error unsubscribing from topic:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Send data-only message
exports.sendDataMessage = async (req, res) => {
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
    
    res.status(200).json({
      success: true,
      message: 'Data message sent successfully',
      messageId: response
    });
  } catch (error) {
    console.error('Error sending data message:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Delete/Invalidate Token
exports.deleteToken = async (req, res) => {
  try {
    const { userId } = req.body;

    await db.ref(`fcmTokens/${userId}`).update({ 
      isActive: false,
      deletedAt: admin.database.ServerValue.TIMESTAMP
    });

    res.status(200).json({
      success: true,
      message: 'Token invalidated successfully'
    });
  } catch (error) {
    console.error('Error deleting token:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// Send to user by userId
exports.notifyUser = async (req, res) => {
  try {
    const { userId, data } = req.body;
    
    const title = sanitizeString(req.body.title, 100);
    const body = sanitizeString(req.body.body, 500);

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
          sound: 'default',
          channelId: 'default_channel'
        }
      },
      token: tokenData.token
    };

    const response = await admin.messaging().send(message);

    res.status(200).json({
      success: true,
      message: 'Notification sent successfully',
      messageId: response
    });
  } catch (error) {
    console.error('Error notifying user:', error);
    
    if (error.code === 'messaging/invalid-registration-token' ||
        error.code === 'messaging/registration-token-not-registered') {
      await db.ref(`fcmTokens/${req.body.userId}`).update({ isActive: false });
    }
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};
