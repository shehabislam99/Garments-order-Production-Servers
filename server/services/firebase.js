const admin = require("firebase-admin");

let firebaseEnabled = false;

const initializeFirebase = () => {
  if (firebaseEnabled) return;

  const encodedKey = process.env.FB_SERVICE_KEY;
  if (!encodedKey) return;

  try {
    const decoded = Buffer.from(encodedKey, "base64").toString("utf8");
    const serviceAccount = JSON.parse(decoded);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });

    firebaseEnabled = true;
  } catch (error) {
    firebaseEnabled = false;
  }
};

const verifyFirebaseToken = async (idToken) => {
  if (!firebaseEnabled) return null;
  return admin.auth().verifyIdToken(idToken);
};

module.exports = {
  initializeFirebase,
  verifyFirebaseToken,
};
