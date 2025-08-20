const passport = require('passport');

const Admin = require('../models/Admin');
const Manager = require('../models/Manager');
const Employee = require('../models/Employee');
require('dotenv').config();

/**
 * Serialize user for session
 */
passport.serializeUser((user, done) => {
  done(null, { id: user._id, role: user.role });
});

/**
 * Deserialize user from session
 */
passport.deserializeUser(async (userData, done) => {
  try {
    let user = null;
    
    if (userData.role === 'admin') {
      user = await Admin.findById(userData.id).select('-password');
    } else if (userData.role === 'manager') {
      user = await Manager.findById(userData.id).select('-password');
    } else if (userData.role === 'employee') {
      user = await Employee.findById(userData.id).select('-password');
    }
    
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport;
