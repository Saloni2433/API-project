const { validationResult } = require('express-validator');
const Manager = require("../models/Manager");
const Employee = require("../models/Employee");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");

require("dotenv").config();

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

/**
 * @desc    Create new manager (Admin only)
 * @route   POST /api/managers
 * @access  Private (Admin)
 */
const createManager = async (req, res) => {
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

    const { username, email, password, phone, department } = req.body;
    if (
      typeof username !== "string" ||
      !username.trim() ||
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      !password.trim() ||
      typeof phone !== "string" ||
      !phone.trim() ||
      typeof department !== "string" ||
      !department.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required and must be non-empty strings.",
      });
    }

    // Check if manager already exists by email
    const existingManagerByEmail = await Manager.findByEmail(email);
    if (existingManagerByEmail) {
      return res.status(400).json({
        success: false,
        message: "Manager with this email already exists",
      });
    }

    // Check if manager already exists by username
    const existingManagerByUsername = await Manager.findOne({
      username: username.toLowerCase(),
    });
    if (existingManagerByUsername) {
      return res.status(400).json({
        success: false,
        message: "Manager with this username already exists",
      });
    }

    // Handle image upload
    let imagePath = null;
    if (req.file) {
      imagePath = req.file.filename;
    }

    // Create manager
    const manager = await Manager.create({
      username: username.toLowerCase(),
      email,
      password,
      phone,
      department,
      image: imagePath,
      createdBy: req.user._id,
    });

    // Send welcome email (Temporarily disabled)
    /*
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: "Welcome to Admin Panel - Manager Account",
        html: `
          <h2>Welcome to the Admin Panel!</h2>
          <p>Hello ${name},</p>
          <p>Your manager account has been created successfully.</p>
          <p><strong>Login Details:</strong></p>
          <p>Email: ${email}</p>
          <p>Password: ${password}</p>
          <p>Department: ${department}</p>
          <p>Please change your password after first login.</p>
          <p>Login URL: ${process.env.FRONTEND_URL}/login</p>
        `,
      });
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
    }
    */

    res.status(201).json({
      success: true,
      message: "Manager created successfully",
      data: manager,
    });
  } catch (error) {
    console.error("Manager creation error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during manager creation",
      error: error.message,
    });
  }
};

/**
 * @desc    Manager login
 * @route   POST /api/managers/login
 * @access  Public
 */
const loginManager = async (req, res) => {
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

    // Check for manager by email or username and include password
    let manager;
    if (email.includes("@")) {
      // Login by email
      manager = await Manager.findByEmail(email).select("+password");
    } else {
      // Login by username
      manager = await Manager.findOne({
        username: email.toLowerCase(),
      }).select("+password");
    }

    if (!manager || typeof manager.password !== "string") {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if manager is active
    if (!manager.isActive) {
      return res.status(401).json({
        success: false,
        message: "Account is deactivated",
      });
    }

    // Check password
    const isMatch = await manager.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Update last login
    manager.lastLogin = new Date();
    await manager.save();

    // Generate JWT token and return response
    const token = jwt.sign({ id: manager._id, role: manager.role, email: manager.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });

    res.status(200).json({
      success: true,
      message: "Login successful",
      token: token,
      data: {
        _id: manager._id,
        username: manager.username,
        email: manager.email,
        role: manager.role,
        department: manager.department,
        image: manager.image,
        lastLogin: manager.lastLogin,
      },
    });
  } catch (error) {
    console.error("Manager login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during login",
      error: error.message,
    });
  }
};

/**
 * @desc    Get manager profile
 * @route   GET /api/managers/profile
 * @access  Private (Manager)
 */
const getManagerProfile = async (req, res) => {
  try {
    console.log('User from token:', req.user); // Log the user from token
    
    const manager = await Manager.findById(req.user._id)
      .populate("createdBy", "name email")
      .populate("managedEmployees", "name email position");

    console.log('Found manager:', manager); // Log the found manager

    if (!manager) {
      return res.status(404).json({
        success: false,
        message: "Manager not found"
      });
    }

    res.status(200).json({
      success: true,
      data: manager,
    });
  } catch (error) {
    console.error('Error in getManagerProfile:', error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Update manager profile
 * @route   PUT /api/managers/profile
 * @access  Private (Manager)
 */
const updateManagerProfile = async (req, res) => {
  try {
    const { username, phone } = req.body;

    // Check if username is being updated and if it's already taken
    if (username) {
      const existingManager = await Manager.findOne({
        username: username.toLowerCase(),
        _id: { $ne: req.user._id }, // Exclude current manager
      });
      if (existingManager) {
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

    const manager = await Manager.findByIdAndUpdate(req.user._id, updateData, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
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

/**
 * @desc    Change manager password
 * @route   PUT /api/managers/change-password
 * @access  Private (Manager)
 */
const changePassword = async (req, res) => {
  console.log("manager changePassword route hit");
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

    // Get manager with password
    const manager = await Manager.findById(req.user._id).select("+password");
    console.log("Manager found:", manager);

    // Check current password
    const isMatch = await manager.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Update password
    manager.password = newPassword;
    console.log("Manager password before save:", manager.password);
    await manager.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Manager change password error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Forgot password
 * @route   POST /api/managers/forgot-password
 * @access  Public
 */
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
      const manager = await Manager.findByEmail(email);
      if (manager) {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // Set code and expiry (10 minutes)
        manager.resetCode = code;
        manager.resetCodeExpire = Date.now() + 10 * 60 * 1000;
        await manager.save({ validateBeforeSave: false });

        // Send email
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: email,
          subject: "Your Admin Panel Password",
          html: `
            <h2>Password Reset Code</h2>
            <p>Hello${manager.name ? ` ${manager.name}` : ""},</p>
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
          message: "Email sent.",
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


/**
 * @desc    Reset password
 * @route   PUT /api/managers/reset-password/:resettoken
 * @access  Public
 */
const resetPassword = async (req, res) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.resettoken)
      .digest("hex");

    const manager = await Manager.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!manager) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    // Set new password
    manager.password = req.body.password;
    manager.resetPasswordToken = undefined;
    manager.resetPasswordExpire = undefined;
    await manager.save();

    sendTokenResponse(manager, 200, res, "Password reset successful");
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Create new employee (Manager can create employees in their department)
 * @route   POST /api/managers/employees
 * @access  Private (Manager)
 */
const createEmployee = async (req, res) => {
  try {
    // Log raw request details
    console.log('=== RAW REQUEST ===');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Raw body:', req.body);
    console.log('Parsed body:', JSON.stringify(req.body, null, 2));
    console.log('Content-Type:', req.get('Content-Type'));
    console.log('===================');

    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation errors:', errors.array());
      return res.status(400).json({
        success: false,
        message: "Validation errors",
        errors: errors.array(),
      });
    }

    const { username, email, password, phone, position, employeeId, salary, department } = req.body;
    console.log('Extracted fields:', {
      username,
      email: email ? '***' : 'MISSING',
      phone,
      position,
      employeeId,
      salary,
      department: department || 'MISSING'
    });

    // Validate required fields
    if (typeof username !== 'string' || !username.trim()) {
      return res.status(400).json({
        success: false,
        message: "Username is required and must be a non-empty string.",
        receivedData: JSON.stringify(req.body, null, 2)
      });
    }
    if (typeof department !== 'string' || !department.trim()) {
      return res.status(400).json({
        success: false,
        message: "Department is required and must be a non-empty string.",
        receivedData: JSON.stringify(req.body, null, 2)
      });
    }

    // Check if employee already exists by email
    const existingEmployeeByEmail = await Employee.findByEmail(email);
    if (existingEmployeeByEmail) {
      return res.status(400).json({
        success: false,
        message: "Employee with this email already exists",
      });
    }

    // Check if employee already exists by username
    const existingEmployeeByUsername = await Employee.findOne({
      username: username.toLowerCase(),
    });
    if (existingEmployeeByUsername) {
      return res.status(400).json({
        success: false,
        message: "Employee with this username already exists",
      });
    }

    // Check if employee ID already exists
    const existingEmployeeId = await Employee.findByEmployeeId(employeeId);
    if (existingEmployeeId) {
      return res.status(400).json({
        success: false,
        message: "Employee ID already exists",
      });
    }

    // Handle image upload
    let imagePath = null;
    if (req.file) {
      imagePath = req.file.filename;
    }

    // Create employee with department from request
    const employee = await Employee.create({
      username: username.toLowerCase(),
      email,
      password,
      phone,
      department: department.trim(), // Use department from request
      position,
      employeeId,
      salary: salary || 0,
      image: imagePath,
      createdBy: req.user._id,
      createdByModel: "Manager",
      managedBy: req.user._id,
    });

    // Add employee to manager's managed employees list
    await Manager.findByIdAndUpdate(req.user._id, {
      $push: { managedEmployees: employee._id },
    });

    // Remove password from response
    employee.password = undefined;

    res.status(201).json({
      success: true,
      message: "Employee created successfully",
      data: employee,
    });

  } catch (error) {
    console.error('Error creating employee:', error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Get all employees managed by this manager
 * @route   GET /api/managers/employees
 * @access  Private (Manager)
 */
const getManagedEmployees = async (req, res) => {
  try {
    const employees = await Employee.find({
      $or: [{ managedBy: req.user._id }, { department: req.user.department }],
    })
      .populate("createdBy", "name email")
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

/**
 * @desc    Get single employee details
 * @route   GET /api/managers/employees/:id
 * @access  Private (Manager)
 */
const getEmployeeById = async (req, res) => {
  try {
    const employee = await Employee.findOne({
      _id: req.params.id,
      $or: [{ managedBy: req.user._id }, { department: req.user.department }],
    })
      .populate("createdBy", "name email")
      .populate("managedBy", "name email department");

    if (!employee) {
      return res.status(404).json({
        success: false,
        message: "Employee not found or not in your department",
      });
    }

    res.status(200).json({
      success: true,
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

module.exports = {
  createManager,
  loginManager,
  getManagerProfile,
  updateManagerProfile,
  changePassword,
  forgotPassword,
  createEmployee,
  getManagedEmployees,
  getEmployeeById,
};
