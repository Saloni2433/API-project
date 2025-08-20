


const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'User not authenticated',
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${roles.join(', ')}. Your role: ${req.user.role}`,
      });
    }

    next();
  };
};


const adminOnly = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'User not authenticated',
    });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.',
    });
  }

  next();
};


const managerOrAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'User not authenticated',
    });
  }

  if (!['admin', 'manager'].includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Manager or Admin privileges required.',
    });
  }

  next();
};


const ownerOrAuthorized = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'User not authenticated',
    });
  }

  const userId = req.params.id || req.params.userId;
  const userRole = req.user.role;
  const currentUserId = req.user._id.toString();

  
  if (userRole === 'admin') {
    return next();
  }

  
  if (userRole === 'manager') {
    if (userId === currentUserId) {
      return next();
    }
    
    return next();
  }

  // Employee can only access their own data
  if (userRole === 'employee') {
    if (userId === currentUserId) {
      return next();
    }
    return res.status(403).json({
      success: false,
      message: 'Access denied. You can only access your own data.',
    });
  }

  return res.status(403).json({
    success: false,
    message: 'Access denied.',
  });
};

const canManageEmployee = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'User not authenticated',
    });
  }

  if (req.user.role === 'admin') {
    return next();
  }

  if (req.user.role === 'manager') {
    const Employee = require('../models/Employee');
    const employeeId = req.params.id || req.params.employeeId;
    try {
      const employee = await Employee.findById(employeeId);
      if (!employee) {
        return res.status(404).json({
          success: false,
          message: 'Employee not found',
        });
      }

      if (employee.department === req.user.department || 
          employee.managedBy?.toString() === req.user._id.toString()) {
        return next();
      }

      return res.status(403).json({
        success: false,
        message: 'You can only manage employees in your department',
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: 'Error checking employee permissions',
        error: error.message,
      });
    }
  }

  return res.status(403).json({
    success: false,
    message: 'Access denied. Manager or Admin privileges required.',
  });
};

const webAuthorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      req.flash('error', 'Please log in to access this page');
      return res.redirect('/login');
    }

    if (!roles.includes(req.user.role)) {
      req.flash('error', `Access denied. Required roles: ${roles.join(', ')}`);
      return res.redirect('/dashboard');
    }

    next();
  };
};

module.exports = {
  authorize,
  adminOnly,
  managerOrAdmin,
  ownerOrAuthorized,
  canManageEmployee,
  webAuthorize,
};
