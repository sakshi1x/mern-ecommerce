require("dotenv").config();
const fs = require("fs");
const https = require("https");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const compression = require("compression");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const winston = require("winston");
const { connectToDB } = require("./database/db");

// Load SSL Certificates
const privateKey = fs.readFileSync("server.key", "utf8");
const certificate = fs.readFileSync("server.cert", "utf8");
const credentials = { key: privateKey, cert: certificate };

// Server init
const server = express();

// Database connection
connectToDB();

// Security Middleware
server.use(helmet());
server.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true })); // HSTS
server.use(mongoSanitize());
server.use(xss());
server.use(compression());

// CORS Configuration
server.use(cors({
    origin: process.env.ORIGIN,
    credentials: true,
    exposedHeaders: ["X-Total-Count"],
    methods: ["GET", "POST", "PATCH", "DELETE"]
}));

// Secure Session Management with MongoDB
server.use(session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { secure: true, httpOnly: true, sameSite: "strict", maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// CSRF Protection
server.use(csurf({ cookie: { httpOnly: true, secure: true, sameSite: "strict" } }));

// Dynamic Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: (req, res) => (req.user && req.user.role === "admin" ? 500 : 100), // Higher limit for admins
    message: "Too many requests from this IP, please try again later."
});
server.use(limiter);

// Logging Middleware
const logger = winston.createLogger({
    level: "info",
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: "error.log", level: "error" }),
        new winston.transports.File({ filename: "combined.log" }),
    ],
});
server.use(morgan("tiny"));

// JSON & Cookie Parsing Middleware
server.use(express.json());
server.use(cookieParser());

// CSRF Token Middleware
server.use((req, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken(), { httpOnly: true, secure: true, sameSite: "strict" });
    next();
});

// Routes
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

// Default Route
server.get("/", (req, res) => {
    res.status(200).json({ message: "Server is running securely on HTTPS 🚀" });
});

// Redirect HTTP to HTTPS
const http = require("http");
http.createServer((req, res) => {
    res.writeHead(301, { "Location": `https://${req.headers.host}${req.url}` });
    res.end();
}).listen(8000, () => {
    console.log("🔄 Redirecting all HTTP requests to HTTPS");
});

// Start HTTPS Server
https.createServer(credentials, server).listen(8443, () => {
    console.log("✅ Secure server [STARTED] ~ https://localhost:8443");
});
