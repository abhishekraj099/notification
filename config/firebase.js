const admin = require('firebase-admin');

let serviceAccount;

// Handle different environments
if (process.env.SERVICE_ACCOUNT_BASE64) {
  // For production (Render deployment) - using base64 encoded service account
  const decoded = Buffer.from(process.env.SERVICE_ACCOUNT_BASE64, 'base64').toString();
  serviceAccount = JSON.parse(decoded);
} else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
  // Using individual environment variables
  serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    // CRITICAL: Replace escaped \n with actual newlines
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  };
} else {
  // For local development using JSON file
  serviceAccount = require('../serviceAccountKey.json');
}

// Initialize Firebase Admin SDK only once
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL || "https://notifaction-f0929-default-rtdb.firebaseio.com"
    });
    console.log('✅ Firebase Admin initialized successfully');
  } catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    process.exit(1); // Exit if Firebase fails to initialize
  }
}

const db = admin.database();

module.exports = { admin, db };
