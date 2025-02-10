const mongoose = require("mongoose");
const { Schema } = mongoose;

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        unique: true,
        required: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    passwordHistory: { 
        type: [String], 
        default: undefined  // Won't affect existing users, but will be used for new ones
    },
    passwordLastChanged: { 
        type: Date, 
        default: Date.now  // New users get this, existing ones remain unchanged
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    mfaEnabled: { 
        type: Boolean, 
        default: false  // Default is false for new users
    },
    mfaSecret: { 
        type: String, 
        default: null  // Prevents breaking old users who lack this field
    }
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);
