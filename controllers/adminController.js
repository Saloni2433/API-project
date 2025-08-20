const Admin = require("../models/Admin");
const Manager = require("../models/Manager");
const Employee = require("../models/Employee");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");

require("dotenv").config();
const bcrypt = require("bcryptjs");

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});


const registerAdmin = async (req, res) => {
  console.log(req.body);
  try {
    // Check validation errors

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: "Validation errors",
        errors: errors.array(),
      });
    }

    const { username, email, password, phone } = req.body;
    if (
      typeof username !== "string" ||
      !username.trim() ||
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      !password.trim() ||
      typeof phone !== "string" ||
      !phone.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required and must be non-empty strings.",
      });
    }

    // Check if admin already exists by email
    const existingAdminByEmail = await Admin.findByEmail(email);
    if (existingAdminByEmail) {
      return res.status(400).json({
        success: false,
        message: "Admin with this email already exists",
      });
    }

    // Check if admin already exists by username
    const existingAdminByUsername = await Admin.findOne({
      username: username.toLowerCase(),
    });
    if (existingAdminByUsername) {
      return res.status(400).json({
        success: false,
        message: "Admin with this username already exists",
      });
    }

    // Check if this is the first admin (no authentication required)
    const adminCount = await Admin.countDocuments();
    if (adminCount > 0 && !req.user) {
      return res.status(401).json({
        success: false,
        message: "Only existing admins can create new admins",
      });
    }

    // Handle image upload
    let imagePath = null;
    if (req.file) {
      imagePath = req.file.filename;
    }

    // Create admin
    const admin = await Admin.create({
      username: username.toLowerCase(),
      email,
      password,
      phone,
      image: imagePath,
      createdBy: req.user ? req.user._id : null,
    });

    // Send welcome email (Temporarily disabled)
    /*
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: "Welcome to Admin Panel",
        html: `
          <h2>Welcome to the Admin Panel!</h2>
          <p>Hello ${name},</p>
          <p>Your admin account has been created successfully.</p>
          <p><strong>Login Details:</strong></p>
          <p>Email: ${email}</p>
          <p>Password: ${password}</p>
          <p>Please change your password after first login.</p>
          <p>Login URL: ${process.env.FRONTEND_URL}/login</p>
        `,
      });
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
    }
    */

    sendTokenResponse(admin, 201, res, "Admin registered successfully");
  } catch (error) {
    console.error("Admin registration error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during admin registration",
      error: error.message,
    });
  }
};

const loginAdmin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      !password.trim()
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Email/Username and password are required and must be non-empty strings.",
      });
    }

    // Check for admin by email or username and include password
    let admin;
    if (email.includes("@")) {
      // Login by email
      admin = await Admin.findByEmail(email).select("+password");
    } else {
      // Login by username
      admin = await Admin.findOne({
        username: email.toLowerCase(),
      }).select("+password");
    }

    if (!admin || typeof admin.password !== "string") {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if admin is active
    if (!admin.isActive) {
      return res.status(401).json({
        success: false,
        message: "Account is deactivated",
      });
    }

    // Check password
    const isMatch = await admin.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid password",
      });
    }

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    // Generate JWT token and return response
    const token = jwt.sign({ id: admin._id, role: admin.role, email: admin.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });

    res.status(200).json({
      success: true,
      message: "Login successful",
      token: token,
      data: {
        _id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        image: admin.image,
        lastLogin: admin.lastLogin,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during login",
      error: error.message,
    });
  }
};

const getAdminProfile = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user._id);

    res.status(200).json({
      success: true,
      data: admin,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const updateAdminProfile = async (req, res) => {
  try {
    const { username, phone } = req.body;

    // Check if username is being updated and if it's already taken
    if (username) {
      const existingAdmin = await Admin.findOne({
        username: username.toLowerCase(),
        _id: { $ne: req.user._id }, // Exclude current admin
      });
      if (existingAdmin) {
        return res.status(400).json({
          success: false,
          message: "Username already exists",
        });
      }
    }

    // Handle image upload
    let updateData = { phone };
    if (username) {
      updateData.username = username.toLowerCase();
    }
    if (req.file) {
      updateData.image = req.file.filename;
    }

    const admin = await Admin.findByIdAndUpdate(req.user._id, updateData, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: admin,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};


const changePassword = async (req, res) => {
  console.log("changePassword route hit");
  try {
    const { currentPassword, newPassword } = req.body;
    console.log(
      "currentPassword:",
      currentPassword,
      "newPassword:",
      newPassword
    );

    // Validate input
    if (
      typeof currentPassword !== "string" ||
      !currentPassword.trim() ||
      typeof newPassword !== "string" ||
      !newPassword.trim()
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Current and new password are required and must be non-empty strings.",
      });
    }

    // Get admin with password
    const admin = await Admin.findById(req.user._id).select("+password");
    console.log("Admin found:", admin);

    // Check current password
    const isMatch = await admin.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Update password
    admin.password = newPassword;
    console.log("Admin password before save:", admin.password);
    await admin.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (typeof email !== "string" || !email.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email is required and must be a non-empty string",
      });
    }

    // Always respond with success for privacy
    let responseSent = false;
    try {
      const admin = await Admin.findByEmail(email);
      if (admin) {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // Set code and expiry (10 minutes)
        admin.resetCode = code;
        admin.resetCodeExpire = Date.now() + 10 * 60 * 1000;
        await admin.save({ validateBeforeSave: false });

        // Send email
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: email,
          subject: "Your Admin Panel Password",
          html: `
            <h2>Password Reset Code</h2>
            <p>Hello${admin.name ? ` ${admin.name}` : ""},</p>
            <p>Your password reset code is:</p>
            <div style="font-size:2em; font-weight:bold; letter-spacing:4px;">${code}</div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
          `,
        });
      }
      // Always respond with success
      if (!responseSent) {
        responseSent = true;
        return res.status(200).json({
          success: true,
          message: "Emial sent.",
        });
      }
    } catch (err) {
      // Don't reveal errors to user
      if (!responseSent) {
        responseSent = true;
        return res.status(200).json({
          success: true,
          message: "Email sent.",
        });
      }
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, code, and new password are required.",
      });
    }
    const admin = await Admin.findOne({ email });
    if (!admin || !admin.resetCode || !admin.resetCodeExpire) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired code.",
      });
    }
    if (
      admin.resetCode !== code ||
      admin.resetCodeExpire < Date.now()
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired code.",
      });
    }
    admin.password = newPassword;
    admin.resetCode = undefined;
    admin.resetCodeExpire = undefined;
    await admin.save();
    return res.status(200).json({
      success: true,
      message: "Password reset successful. You can now log in with your new password.",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const getAllManagers = async (req, res) => {
  try {
    const managers = await Manager.find()
      .populate("createdBy", "name email")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: managers.length,
      data: managers,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const getAllEmployees = async (req, res) => {
  try {
    const employees = await Employee.find()
      .populate("createdBy", "name email")
      .populate("managedBy", "name email department")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: employees.length,
      data: employees,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const toggleManagerStatus = async (req, res) => {
  try {
    const manager = await Manager.findById(req.params.id);

    if (!manager) {
      return res.status(404).json({
        success: false,
        message: "Manager not found",
      });
    }

    manager.isActive = !manager.isActive;
    await manager.save();

    res.status(200).json({
      success: true,
      message: `Manager ${
        manager.isActive ? "activated" : "deactivated"
      } successfully`,
      data: manager,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

const toggleEmployeeStatus = async (req, res) => {
  try {
    const employee = await Employee.findById(req.params.id);

    if (!employee) {
      return res.status(404).json({
        success: false,
        message: "Employee not found",
      });
    }

    employee.isActive = !employee.isActive;
    await employee.save();

    res.status(200).json({
      success: true,
      message: `Employee ${
        employee.isActive ? "activated" : "deactivated"
      } successfully`,
      data: employee,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Get dashboard statistics
const getDashboardStats = async (req, res) => {
  try {
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
};

module.exports = {
  registerAdmin,
  loginAdmin,
  getAdminProfile,
  updateAdminProfile,
  changePassword,
  forgotPassword,
  getAllManagers,
  getAllEmployees,
  toggleManagerStatus,
  toggleEmployeeStatus,
  getDashboardStats,
};
