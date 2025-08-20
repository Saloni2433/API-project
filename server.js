const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("./config/passport");
const { requireLogin } = require("./middleware/authMiddleware");
const connectDB = require("./config/db");
require("dotenv").config();


const adminRoutes = require("./routes/adminRoutes");
const managerRoutes = require("./routes/managerRoutes");
const employeeRoutes = require("./routes/employeeRoutes");
const Admin = require("./models/Admin");
const bcrypt = require("bcryptjs");
const Manager = require("./models/Manager");
const Employee = require("./models/Employee");


const app = express();


connectDB();


app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);


app.use(passport.initialize());
app.use(passport.session());




app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use((req, res, next) => {
  console.log('Incoming request:', {
    method: req.method,
    url: req.url,
    body: req.body,
    headers: req.headers['content-type']
  });
  next();
});


app.use("/api/admin", adminRoutes);
app.use("/api/managers", managerRoutes);
app.use("/api/employees", employeeRoutes);


app.post("/api/login", async (req, res) => {
  console.log('Login attempt:', req.body);
  
  try {
    const { emailOrUsername, password, role } = req.body;
    
    
    if (!emailOrUsername || !password || !role) {
      console.log('Missing required fields');
      return res.status(400).json({
        success: false,
        message: 'Please fill in all fields',
      });
    }

    let user;
    const email = emailOrUsername.trim().toLowerCase();

    
    if (role === 'admin') {
      user = await Admin.findOne({ email }).select('+password');
    } else if (role === 'manager') {
      user = await Manager.findOne({ email }).select('+password');
    } else if (role === 'employee') {
      user = await Employee.findOne({ email }).select('+password');
    } else {
      return res.status(400).json({
        success: false,
        message: 'Invalid role specified',
      });
    }

    
    if (!user) {
      console.log('User not found:', email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Invalid password for user:', email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Update last login time
    user.lastLogin = new Date();
    await user.save();

    // Prepare user data for response
    const userData = {
      id: user._id,
      name: user.name || user.username || 'User',
      email: user.email,
      role: role,
      createdAt: user.createdAt
    };

    // Return user data in response
    console.log('Login successful for:', user.email);
    return res.json({
      success: true,
      data: userData
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.render('login', { 
      title: 'Login - Admin Panel',
      error: 'An error occurred during login',
      emailOrUsername: req.body.emailOrUsername || '',
      email: req.body.emailOrUsername || '',
      role: req.body.role || ''
    });
  }
});

// Removed generic dashboard route - using role-specific dashboards instead

// Admin dashboard stats API (must come before dashboard route)
app.get("/admin/dashboard/stats", requireLogin, async (req, res) => {
  console.log("Dashboard stats route hit");
  console.log("User:", req.user);
  console.log("URL:", req.originalUrl);

  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied. Admin role required.",
      });
    }

    // Get total employees count
    const totalEmployees = await Employee.countDocuments();

    // Get active managers count
    const activeManagers = await Manager.countDocuments({ isActive: true });

    // Get pending requests (example: employees without managers)
    const pendingRequests = await Employee.countDocuments({
      managedBy: { $exists: false },
    });

    // Calculate system uptime (example: days since first user was created)
    const firstUser = await Admin.findOne().sort({ createdAt: 1 });
    const systemUptime = firstUser
      ? Math.floor(
          (Date.now() - new Date(firstUser.createdAt).getTime()) /
            (1000 * 60 * 60 * 24)
        )
      : 0;

    // Get recent activity (last 7 days logins)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const recentActivity = await Promise.all([
      Admin.countDocuments({ lastLogin: { $gte: sevenDaysAgo } }),
      Manager.countDocuments({ lastLogin: { $gte: sevenDaysAgo } }),
      Employee.countDocuments({ lastLogin: { $gte: sevenDaysAgo } }),
    ]);

    const totalRecentLogins = recentActivity.reduce(
      (sum, count) => sum + count,
      0
    );

    res.json({
      success: true,
      data: {
        totalEmployees,
        activeManagers,
        pendingRequests,
        systemUptime,
        totalRecentLogins,
        recentActivity: {
          admins: recentActivity[0],
          managers: recentActivity[1],
          employees: recentActivity[2],
        },
      },
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch dashboard statistics",
      error: error.message,
    });
  }
});

// Removed dashboard/profile UI routes. All dashboard/profile logic should be handled by /api endpoints and return JSON.

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
    }
    res.redirect("/login");
  });
});

// Test route to check admin account
app.get("/test-admin", async (req, res) => {
  try {
    const admins = await Admin.find({});
    res.json({
      success: true,
      count: admins.length,
      admins: admins.map((admin) => ({
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      })),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Removed admin management UI routes for adding managers/employees. All such logic should be handled by /api endpoints.

app.put("/test-body", (req, res) => {
  res.json({
    body: req.body,
    headers: req.headers,
    type: typeof req.body,
    isArray: Array.isArray(req.body),
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Server is running",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// API documentation endpoint
app.get("/api", (req, res) => {
  res.json({
    success: true,
    message: "Admin Panel API",
    version: "1.0.0",
    endpoints: {
      admin: {
        register: "POST /api/admin/register",
        login: "POST /api/admin/login",
        profile: "GET /api/admin/profile",
        changePassword: "PUT /api/admin/change-password",
        forgotPassword: "POST /api/admin/forgot-password",
        managers: "GET /api/admin/managers",
        // toggleManagerStatus: "PUT /api/admin/managers/:id/toggle-status",
        employees: "GET /api/admin/employees",
        // toggleEmployeeStatus: "PUT /api/admin/employees/:id/toggle-status",
      },
      manager: {
        login: "POST /api/managers/login",
        profile: "GET /api/managers/profile",
        changePassword: "PUT /api/managers/change-password",
        forgotPassword: "POST /api/managers/forgot-password",
        createEmployee: "POST /api/managers/employees",
        employees: "GET /api/managers/employees",
      },
      employee: {
        login: "POST /api/employees/login",
        profile: "GET /api/employees/profile",
        changePassword: "PUT /api/employees/change-password",
        forgotPassword: "POST /api/employees/forgot-password",
      },
    },
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found",
  });
});


app.use((err, req, res, next) => {
  console.error("Global error handler:", err);

  
  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({
      success: false,
      message: "Validation Error",
      errors,
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: `${field} already exists`,
    });
  }

  // JWT errors
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }

  if (err.name === "TokenExpiredError") {
    return res.status(401).json({
      success: false,
      message: "Token expired",
    });
  }

  // Default error
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Admin Panel Server running on port ${PORT}`);
  console.log(`📱 Web Interface: http://localhost:${PORT}`);
  console.log(`🔗 API Documentation: http://localhost:${PORT}/api`);
  console.log(`💚 Health Check: http://localhost:${PORT}/health`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log("\n📋 Available Endpoints:");
  console.log("   • Admin Login: POST /api/admin/login");
  console.log("   • Manager Login: POST /api/managers/login");
  console.log("   • Employee Login: POST /api/employees/login");
  console.log("   • Web Login: GET /login");
  console.log("\n⚡ Ready to accept connections!\n");
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("\n🛑 SIGTERM received. Shutting down gracefully...");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("\n🛑 SIGINT received. Shutting down gracefully...");
  process.exit(0);
});

module.exports = app;
