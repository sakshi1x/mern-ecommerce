require("dotenv").config();
const fs = require("fs");
const https = require("https");
const http = require("http");
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

// Initialize Server
const server = express();

// Database connection
connectToDB();

// 🔄 Force HTTPS Middleware (Only in Production)
server.use((req, res, next) => {
    if (!req.secure && process.env.NODE_ENV === "production") {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

// 🛡️ Security Middleware
server.use(helmet());
server.use(mongoSanitize());
server.use(xss());
server.use(compression());

// 🔄 CORS Configuration (Allow frontend)
server.use(cors({
    origin: "http://localhost:3000",
    credentials: true,
    exposedHeaders: ["X-Total-Count"],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
}));

// 🏗️ JSON & Cookie Parsing Middleware (Before CSRF)
server.use(express.json());
server.use(cookieParser());

// ⏳ Secure Session Management (Before CSRF)
server.use(session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { 
        secure: process.env.NODE_ENV === "production", 
        httpOnly: true, 
        sameSite: "strict", 
        maxAge: 30 * 24 * 60 * 60 * 1000 
    }
}));

// 🔐 CSRF Protection (After Session)
server.use(csurf({ cookie: { httpOnly: false, secure: process.env.NODE_ENV === "production", sameSite: "strict" } }));


// 🛠️ Logging Middleware
const logger = winston.createLogger({
    level: "info",
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: "error.log", level: "error" }),
        new winston.transports.File({ filename: "combined.log" }),
    ],
});
server.use(morgan("tiny", { stream: { write: (message) => logger.info(message.trim()) } }));

// 🎟️ CSRF Token Middleware (Send Token to Frontend)
server.use((req, res, next) => {
    const csrfToken = req.csrfToken();
    console.log("CSRF Token:", csrfToken); 
    res.cookie("XSRF-TOKEN", req.csrfToken(), { 
        httpOnly: false, // ✅ Allow frontend access
        secure: process.env.NODE_ENV === "production", 
        sameSite: "lax"
    });
    next();
});

// 🚧 CSRF Error Handling
server.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        return res.status(403).json({ error: "CSRF token validation failed." });
    }
    next(err);
});

// ⏳ Dynamic Rate Limiting (Admins get higher limit)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: (req, res) => (req.user && req.user.role === "admin" ? 500 : 100),
    message: "Too many requests from this IP, please try again later."
});
server.use(limiter);

// 🚀 API Routes
server.use("/auth", require("./routes/Auth"));
server.use("/users", require("./routes/User"));
server.use("/products", require("./routes/Product"));
server.use("/orders", require("./routes/Order"));
server.use("/cart", require("./routes/Cart"));
server.use("/brands", require("./routes/Brand"));
server.use("/categories", require("./routes/Category"));
server.use("/address", require("./routes/Address"));
server.use("/reviews", require("./routes/Review"));
server.use("/wishlist", require("./routes/Wishlist"));

// ✅ Default Route
server.get("/", (req, res) => {
    res.status(200).json({ message: "Server is running securely on HTTPS 🚀" });
});

// 🔐 Start HTTPS Server
https.createServer(credentials, server).listen(8443, () => {
    console.log("✅ Secure server [STARTED] ~ https://localhost:8443");
});

// 🔄 Optional HTTP to HTTPS Redirection (Only in Production)
if (process.env.NODE_ENV === "production") {
    http.createServer((req, res) => {
        res.writeHead(301, { "Location": `https://${req.headers.host}${req.url}` });
        res.end();
    }).listen(8000, () => {
        console.log("🔄 Redirecting all HTTP requests to HTTPS");
    });
}
