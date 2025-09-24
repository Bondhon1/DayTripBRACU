import { auth, provider } from "./firebase-config.js";

import { createUserWithEmailAndPassword,
         signInWithEmailAndPassword,
         signInWithPopup,
         sendPasswordResetEmail } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-auth.js";
import { sendEmailVerification } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-auth.js";



/* == UI - Elements == */
const signInWithGoogleButtonEl = document.getElementById("sign-in-with-google-btn")
const signUpWithGoogleButtonEl = document.getElementById("sign-up-with-google-btn")
const emailInputEl = document.getElementById("email-input")
const passwordInputEl = document.getElementById("password-input")
const signInButtonEl = document.getElementById("sign-in-btn")
const createAccountButtonEl = document.getElementById("create-account-btn")
const emailForgotPasswordEl = document.getElementById("email-forgot-password")
const forgotPasswordButtonEl = document.getElementById("forgot-password-btn")

const errorMsgEmail = document.getElementById("email-error-message")
const errorMsgPassword = document.getElementById("password-error-message")
const errorMsgGoogleSignIn = document.getElementById("google-signin-error-message")



/* == UI - Event Listeners == */
if (signInWithGoogleButtonEl && signInButtonEl) {
    signInWithGoogleButtonEl.addEventListener("click", authSignInWithGoogle)
    signInButtonEl.addEventListener("click", authSignInWithEmail)
}

if (createAccountButtonEl) {
    createAccountButtonEl.addEventListener("click", authCreateAccountWithEmail)
}

if (signUpWithGoogleButtonEl) {
    signUpWithGoogleButtonEl.addEventListener("click", authSignUpWithGoogle)
}

if (forgotPasswordButtonEl) {
    forgotPasswordButtonEl.addEventListener("click", resetPassword)
}

/* === Main Code === */

/* = Functions - Firebase - Authentication = */

// Function to sign in with Google authentication
async function authSignInWithGoogle() {
    provider.setCustomParameters({
        prompt: 'select_account'
    });

    try {
        const result = await signInWithPopup(auth, provider);
        const user = result.user;
        const email = user.email;

        if (!email.endsWith("@g.bracu.ac.bd")) {
            await auth.signOut();
            alert("Only @g.bracu.ac.bd accounts are allowed.");
            return;
        }

        if (!user.emailVerified) {
            await sendEmailVerification(user);
            alert("Please verify your email before logging in. A new verification link was sent.");
            await auth.signOut();
            return;
        }

        const idToken = await user.getIdToken();
        loginUser(user, idToken);

    } catch (error) {
        console.error("Google sign-in error:", error);
        errorMsgGoogleSignIn.textContent = "Google sign-in failed. Please try again.";
    }
}


// Function to create new account with Google auth - will also sign in existing users
async function authSignUpWithGoogle() {
    provider.setCustomParameters({
        prompt: 'select_account'
    });

    try {
        const result = await signInWithPopup(auth, provider);
        const user = result.user;
        const email = user.email;

        if (!email.endsWith("@g.bracu.ac.bd")) {
            await auth.signOut();
            alert("Only BRAC University g-suites accounts are allowed.");
            return;
        }

        // Send verification email if not verified
        if (!user.emailVerified) {
            await sendEmailVerification(user);
            alert("Verification email sent! Please verify before continuing.");
            await auth.signOut();
            return;
        }

        await addNewUserToFirestore(user);
        const idToken = await user.getIdToken();
        loginUser(user, idToken);

    } catch (error) {
        console.error("Google signup error: ", error.message);
        errorMsgGoogleSignIn.textContent = "Google sign-up failed. Please try again.";
    }
}

function authSignInWithEmail() {
    const email = emailInputEl.value.trim();
    const password = passwordInputEl.value;

    signInWithEmailAndPassword(auth, email, password)
        .then((userCredential) => {
            const user = userCredential.user;

            if (!user.emailVerified) {
                auth.signOut();
                errorMsgEmail.textContent = "Please verify your email before logging in.";
                return;
            }

            user.getIdToken().then(function(idToken) {
                loginUser(user, idToken);
            });
        })
        .catch((error) => {
            const errorCode = error.code;
            if (errorCode === "auth/invalid-email") {
                errorMsgEmail.textContent = "Invalid email.";
            } else if (errorCode === "auth/invalid-credential") {
                errorMsgPassword.textContent = "Invalid email or password.";
            }
        });
}



function authCreateAccountWithEmail() {
    const email = emailInputEl.value;
    const password = passwordInputEl.value;

    createUserWithEmailAndPassword(auth, email, password)
        .then(async (userCredential) => {
            const user = userCredential.user;

            // Restrict domain
            if (!email.endsWith("@g.bracu.ac.bd")) {
                await auth.signOut();
                alert("Only @g.bracu.ac.bd accounts are allowed.");
                return;
            }

            // Send verification email
            await sendEmailVerification(user);
            alert("Verification email sent! Please check your inbox before logging in.");

            // Store new user in Firestore only AFTER verification
            await addNewUserToFirestore(user);

        })
        .catch((error) => {
            const errorCode = error.code;
            if (errorCode === "auth/invalid-email") {
                errorMsgEmail.textContent = "Invalid email";
            } else if (errorCode === "auth/weak-password") {
                errorMsgPassword.textContent = "Password must be at least 6 characters";
            } else if (errorCode === "auth/email-already-in-use") {
                errorMsgEmail.textContent = "This email is already registered.";
            }
        });
}

async function addNewUserToFirestore(user) {
    const idToken = await user.getIdToken();

    // Send user info to Flask to store in Firestore
    const response = await fetch("/store-user", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${idToken}`
        },
        body: JSON.stringify({
            email: user.email,
            uid: user.uid,
            createdAt: new Date().toISOString()
        })
    });

    if (!response.ok) {
        console.error("Failed to store user in Firestore.");
    }
}


function resetPassword() {
    const emailToReset = emailForgotPasswordEl.value

    clearInputField(emailForgotPasswordEl)

    sendPasswordResetEmail(auth, emailToReset)
    .then(() => {
        // Password reset email sent!
        const resetFormView = document.getElementById("reset-password-view")
        const resetSuccessView = document.getElementById("reset-password-confirmation-page")

        resetFormView.style.display = "none"
        resetSuccessView.style.display = "block"

    })
    .catch((error) => {
        const errorCode = error.code;
        const errorMessage = error.message;
 
    });

}



function loginUser(user, idToken) {
    fetch('/auth', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${idToken}`
        },
        credentials: 'same-origin'  // Ensures cookies are sent with the request
    }).then(response => {
        if (response.ok) {
            window.location.href = '/dashboard';
        } else {
            console.error('Failed to login');
            // Handle errors here
        }
    }).catch(error => {
        console.error('Error with Fetch operation: ', error);
    });
}



// /* = Functions - UI = */
function clearInputField(field) {
	field.value = ""
}

function clearAuthFields() {
	clearInputField(emailInputEl)
	clearInputField(passwordInputEl)
}


