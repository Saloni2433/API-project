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
 * @desc    Employee login
 * @route   POST /api/employees/login
 * @access  Public
 */
const loginEmployee = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login attempt:", email);

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
          "Email and password are required and must be non-empty strings.",
      });
    }

    // Check for employee by email and include password
    const employee = await Employee.findOne({ email: email.toLowerCase() }).select("+password");
    console.log("Employee found:", !!employee);
    if (!employee) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if employee is active
    if (!employee.isActive) {
      return res.status(401).json({
        success: false,
        message: "Account is deactivated",
      });
    }

    const isMatch = await employee.matchPassword(password);
    console.log("Password match:", isMatch);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Update last login
    employee.lastLogin = new Date();
    await employee.save();

    // Generate JWT token and return response
    const token = jwt.sign({ id: employee._id, role: employee.role, email: employee.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });

    res.status(200).json({
      success: true,
      message: "Login successful",
      token: token,
      data: {
        _id: employee._id,
        username: employee.username,
        email: employee.email,
        role: employee.role,
        position: employee.position,
        department: employee.department,
        image: employee.image,
        lastLogin: employee.lastLogin,
      },
    });
  } catch (error) {
    console.error("Employee login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during login",
      error: error.message,
    });
  }
};

/**
 * @desc    Get employee profile
 * @route   GET /api/employees/profile
 * @access  Private (Employee)
 */
const getEmployeeProfile = async (req, res) => {
  try {
    const employee = await Employee.findById(req.user._id)
      .populate("createdBy", "name email")
      .populate("managedBy", "name email department");

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

/**
 * @desc    Update employee profile
 * @route   PUT /api/employees/profile
 * @access  Private (Employee)
 */
const updateEmployeeProfile = async (req, res) => {
  try {
    const { username, phone } = req.body;

    // Check if username is being updated and if it's already taken
    if (username) {
      const existingEmployee = await Employee.findOne({
        username: username.toLowerCase(),
        _id: { $ne: req.user._id }, // Exclude current employee
      });
      if (existingEmployee) {
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

    const employee = await Employee.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
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

/**
 * @desc    Change employee password
 * @route   PUT /api/employees/change-password
 * @access  Private (Employee)
 */
const changePassword = async (req, res) => {
  console.log("employee changePassword route hit");
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

    // Get employee with password
    const employee = await Employee.findById(req.user._id).select("+password");
    console.log("Employee found:", employee);

    // Check current password
    const isMatch = await employee.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Update password
    employee.password = newPassword;
    console.log("Employee password before save:", employee.password);
    await employee.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Employee change password error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Forgot password
 * @route   POST /api/employees/forgot-password
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
      const employee = await Employee.findByEmail(email);
      if (employee) {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // Set code and expiry (10 minutes)
        employee.resetCode = code;
        employee.resetCodeExpire = Date.now() + 10 * 60 * 1000;
        await employee.save({ validateBeforeSave: false });

        // Send email
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: email,
          subject: "Your Admin Panel Password",
          html: `
            <h2>Password Reset Code</h2>
            <p>Hello${employee.name ? ` ${employee.name}` : ""},</p>
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
 * @route   PUT /api/employees/reset-password/:resettoken
 * @access  Public
 */
const resetPassword = async (req, res) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.resettoken)
      .digest("hex");

    const employee = await Employee.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!employee) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    // Set new password
    employee.password = req.body.password;
    employee.resetPasswordToken = undefined;
    employee.resetPasswordExpire = undefined;
    await employee.save();

    sendTokenResponse(employee, 200, res, "Password reset successful");
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc    Get employee dashboard data
 * @route   GET /api/employees/dashboard
 * @access  Private (Employee)
 */
const getDashboardData = async (req, res) => {
  try {
    const employee = await Employee.findById(req.user._id)
      .populate("managedBy", "name email")
      .select("-password");

    // Get department colleagues (optional)
    const colleagues = await Employee.find({
      department: employee.department,
      _id: { $ne: employee._id },
      isActive: true,
    })
      .select("name email position")
      .limit(5);

    res.status(200).json({
      success: true,
      data: {
        employee,
        colleagues,
        stats: {
          totalColleagues: colleagues.length,
          department: employee.department,
          position: employee.position,
          joiningDate: employee.joiningDate,
        },
      },
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
  loginEmployee,
  getEmployeeProfile,
  updateEmployeeProfile,
  changePassword,
  forgotPassword,
  getDashboardData,
};
