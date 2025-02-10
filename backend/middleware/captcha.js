const { RecaptchaV2 } = require("express-recaptcha"); // If you're using express-recaptcha for CAPTCHA
// const { verifyCaptcha } = require('../utils/verifyCaptcha'); // Function to validate CAPTCHA

// Initialize CAPTCHA with Google reCAPTCHA keys
const recaptcha = new RecaptchaV2({
    siteKey: process.env.RECAPTCHA_SITE_KEY,
    secretKey: process.env.RECAPTCHA_SECRET_KEY,
});
// 
// Store failed login attempts (use a DB or Redis in production for scalability)
let failedLoginAttempts = {}; // In-memory storage (replace with Redis for production)

// Middleware to track failed login attempts
const trackLoginAttempts = (req, res, next) => {
    const ip = req.ip; // You can also track by user ID from the session or JWT if available
    if (!failedLoginAttempts[ip]) {
        failedLoginAttempts[ip] = 0;
    }
    failedLoginAttempts[ip]++;

    // Lockout after 5 failed attempts
    if (failedLoginAttempts[ip] > 5) {
        return res.status(429).json({ message: "Too many failed attempts. Please try again later." });
    }
    next();
};

// Middleware to check for CAPTCHA after multiple failed attempts
const checkForCaptcha = (req, res, next) => {
    const ip = req.ip;
    if (failedLoginAttempts[ip] > 3) { // Show CAPTCHA after 3 failed attempts
        recaptcha.render((err, data) => {
            if (err) {
                return res.status(500).json({ message: "Error loading CAPTCHA" });
            }
            req.recaptchaData = data; // Save CAPTCHA data for rendering in the frontend
            next();
        });
    } else {
        next();
    }
};

const verifyCaptcha = async (captchaResponse) => {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: secretKey,
                response: captchaResponse,
            },
        });

        if (response.data.success) {
            return true; // CAPTCHA verification succeeded
        }
        return false; // CAPTCHA verification failed
    } catch (error) {
        console.error('Error verifying CAPTCHA:', error);
        return false; // Return false if there's an error during verification
    }
};
// Function to verify CAPTCHA response
const verifyCaptchaResponse = (req, res, next) => {
    const captchaResponse = req.body.captchaResponse;

    if (failedLoginAttempts[req.ip] > 3 && !captchaResponse) {
        return res.status(400).json({ message: "CAPTCHA is required." });
    }

    if (failedLoginAttempts[req.ip] > 3 && !verifyCaptcha(captchaResponse)) {
        return res.status(400).json({ message: "CAPTCHA verification failed." });
    }

    next();
};

module.exports = {
    trackLoginAttempts,
    checkForCaptcha,
    verifyCaptchaResponse,
};