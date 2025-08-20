require('dotenv').config();
console.log("authMiddleware loaded");

const requireLogin = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    if (req.user && req.user.isActive) {
      return next();
    }
    return res.status(401).json({
      success: false,
      message: 'Account is deactivated',
    });
  }
  
  return res.status(401).json({
    success: false,
    message: 'Please log in to access this resource',
  });
};



const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const Manager = require('../models/Manager');
const Employee = require('../models/Employee');

const verifyToken = async (req, res, next) => {
  let token;
  console.log("verifyToken middleware called");
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      let user = null;
      if (decoded.role === 'admin') user = await Admin.findById(decoded.id).select('-password');
      else if (decoded.role === 'manager') user = await Manager.findById(decoded.id).select('-password');
      else if (decoded.role === 'employee') user = await Employee.findById(decoded.id).select('-password');
      if (!user || !user.isActive) {
        return res.status(401).json({ success: false, message: 'Not authorized, user not found or inactive' });
      }
      req.user = user;
      next();
    } catch (err) {
      return res.status(401).json({ success: false, message: 'Not authorized, token failed', error: err.message });
    }
  } else {
    return res.status(401).json({ success: false, message: 'Not authorized, no token provided' });
  }
};


const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
      email: user.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE || '7d',
    }
  );
};


const sendTokenResponse = (user, statusCode, res, message = 'Success') => {
  
  const token = generateToken(user);

  const options = {
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    httpOnly: true,
  };

  
  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }

  res.status(statusCode).cookie('token', token, options).json({
    success: true,
    message,
    token,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
    },
  });
};

module.exports = {
  requireLogin,
  verifyToken,
  generateToken,
  sendTokenResponse,    
}
