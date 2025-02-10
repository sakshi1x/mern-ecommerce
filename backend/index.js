require("dotenv").config();
const fs = require("fs");
const https = require("https");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const csrf = require("csurf");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const compression = require("compression");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const winston = require("winston");
const { connectToDB } = require("./database/db");

// Import routes
const authRoutes = require("./routes/Auth");
const productRoutes = require("./routes/Product");
const orderRoutes = require("./routes/Order");
const cartRoutes = require("./routes/Cart");
const brandRoutes = require("./routes/Brand");
const categoryRoutes = require("./routes/Category");
const userRoutes = require("./routes/User");
const addressRoutes = require("./routes/Address");
const reviewRoutes = require("./routes/Review");
const wishlistRoutes = require("./routes/Wishlist");

// Load SSL Certificates
const privateKey = fs.readFileSync("server.key", "utf8");
const certificate = fs.readFileSync("server.cert", "utf8");
const credentials = { key: privateKey, cert: certificate };

// Server init
const server = express();

// Database connection
connectToDB();

// Security Middlewares
server.use(helmet()); // Set security-related HTTP headers
server.use(mongoSanitize()); // Sanitize data to prevent MongoDB operator injection
server.use(xss()); // Prevent XSS attacks
server.use(compression()); // Compress responses to improve performance

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
});
server.use(limiter);

// CORS configuration
server.use(
    cors({
        origin: process.env.ORIGIN,
        credentials: true,
        exposedHeaders: ["X-Total-Count", "XSRF-TOKEN"],
        methods: ["GET", "POST", "PATCH", "DELETE"],
    })
);

// Body parsing and cookie parsing
server.use(express.json());
server.use(cookieParser());
server.use(morgan("tiny")); // Logging

// Session middleware with MongoStore for session persistence
server.use(
    session({
        secret: process.env.SESSION_SECRET || "supersecretkey",
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }), // Store sessions in MongoDB
        cookie: {
            secure: true, // Ensure cookies are only sent over HTTPS
            httpOnly: true,
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        },
    })
);

// CSRF middleware
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: true, // Ensure CSRF cookies are only sent over HTTPS
        sameSite: "lax",
    },
});
server.use(csrfProtection);

// Send CSRF token to the frontend
server.use((req, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken(), {
        httpOnly: false,
        secure: true,
        sameSite: "lax",
    });
    next();
});

// Route middleware
server.use("/auth", authRoutes);
server.use("/users", userRoutes);
server.use("/products", productRoutes);
server.use("/orders", orderRoutes);
server.use("/cart", cartRoutes);
server.use("/brands", brandRoutes);
server.use("/categories", categoryRoutes);
server.use("/address", addressRoutes);
server.use("/reviews", reviewRoutes);
server.use("/wishlist", wishlistRoutes);

// Default route
server.get("/", (req, res) => {
    res.status(200).json({ message: "running" });
});

// CSRF error handling
server.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        return res.status(403).json({ error: "CSRF token validation failed." });
    }
    next(err);
});

// Create HTTPS server
const httpsServer = https.createServer(credentials, server);

// Start HTTPS server
httpsServer.listen(8000, () => {
    console.log("HTTPS server [STARTED] ~ https://localhost:8000");
});