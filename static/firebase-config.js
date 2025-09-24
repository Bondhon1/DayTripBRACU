// firebase-config.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-app.js";
import { getAuth, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-firestore.js";

let auth, provider, db;

// Immediately fetch config from Flask backend
const res = await fetch("/firebase-config");
const firebaseConfig = await res.json();

// Initialize Firebase
const app = initializeApp(firebaseConfig);
auth = getAuth(app);
provider = new GoogleAuthProvider();
db = getFirestore(app);

export { auth, provider, db };
