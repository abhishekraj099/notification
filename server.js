const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
require('dotenv').config();

// Initialize Firebase Admin SDK - Handle both local and deployed environments
let serviceAccount;

if (process.env.SERVICE_ACCOUNT_BASE64) {
  // For Render deployment - using base64 encoded service account
  const decoded = Buffer.from(process.env.SERVICE_ACCOUNT_BASE64, 'base64').toString();
  serviceAccount = JSON.parse(decoded);
} else if (process.env.NODE_ENV === 'production') {
  // For Render using Secret File
  serviceAccount = require('./serviceAccountKey.json');
} else {
  // For local development
  serviceAccount = require('./serviceAccountKey.json');
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://notifaction-f0929-default-rtdb.firebaseio.com"
});

const app = express();
const db = admin.database();

app.use(express.json());
app.use(cors());

// Health check
app.get('/', (req, res) => {
  res.json({ 
    message: 'Firebase Notification API is running!',
    status: 'active',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ✅ NEW: Save/Update FCM Token
app.post('/api/save-token', async (req, res) => {
  try {
    const { userId, token, deviceInfo } = req.body;

    if (!userId || !token) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: userId, token'
      });
    }

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
});

// ✅ UPDATED: Send notification with token validation
app.post('/api/send-notification', async (req, res) => {
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

    if (!fcmToken || !title || !body) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
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
});

// Send notification to multiple devices
app.post('/api/send-multicast', async (req, res) => {
  try {
    const { tokens, title, body, data } = req.body;

    if (!tokens || !Array.isArray(tokens) || tokens.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'tokens must be a non-empty array'
      });
    }

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: title, body'
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
});

// Send notification to a topic
app.post('/api/send-topic', async (req, res) => {
  try {
    const { topic, title, body, data } = req.body;

    if (!topic || !title || !body) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: topic, title, body'
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
});

// Subscribe device(s) to topic
app.post('/api/subscribe-topic', async (req, res) => {
  try {
    const { tokens, topic } = req.body;

    if (!tokens || !topic) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: tokens (array), topic'
      });
    }

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
});

// Unsubscribe device(s) from topic
app.post('/api/unsubscribe-topic', async (req, res) => {
  try {
    const { tokens, topic } = req.body;

    if (!tokens || !topic) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: tokens (array), topic'
      });
    }

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
});

// Send data-only message
app.post('/api/send-data', async (req, res) => {
  try {
    const { token, data } = req.body;

    if (!token || !data) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: token, data'
      });
    }

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
});

// ✅ NEW: Delete/Invalidate Token
app.post('/api/delete-token', async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'Missing userId'
      });
    }

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
});

// ✅ NEW: Get user's active token
app.get('/api/token/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const snapshot = await db.ref(`fcmTokens/${userId}`).once('value');
    const tokenData = snapshot.val();

    if (!tokenData) {
      return res.status(404).json({
        success: false,
        error: 'No token found for this user'
      });
    }

    res.status(200).json({
      success: true,
      data: tokenData
    });
  } catch (error) {
    console.error('Error fetching token:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ✅ NEW: Send to user by userId (no need to know token)
app.post('/api/notify-user', async (req, res) => {
  try {
    const { userId, title, body, data } = req.body;

    if (!userId || !title || !body) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: userId, title, body'
      });
    }

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
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {  // ✅ Changed to listen on all interfaces
  console.log(`🚀 Notification API running on port ${PORT}`);
  console.log(`📱 Ready to send Firebase notifications!`);
  console.log(`🌐 Health check: http://localhost:${PORT}/`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
});
