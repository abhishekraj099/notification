const admin = require('firebase-admin');

if (!admin.apps.length) {
  try {
    // For Render deployment with full service account JSON
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
      const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString();
      const serviceAccount = JSON.parse(decoded);
      
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: "https://notifaction-f0929-default-rtdb.firebaseio.com"
      });
      
      console.log('✅ Firebase Admin initialized successfully (Base64)');
    } else {
      // For local development
      const serviceAccount = require('../serviceAccountKey.json');
      
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: "https://notifaction-f0929-default-rtdb.firebaseio.com"
      });
      
      console.log('✅ Firebase Admin initialized successfully (Local JSON)');
    }
    
    console.log('✅ Project:', admin.app().options.credential.projectId);
  } catch (error) {
    console.error('❌ Firebase initialization error:', error);
    throw error;
  }
}

const db = admin.database();

module.exports = { admin, db };
