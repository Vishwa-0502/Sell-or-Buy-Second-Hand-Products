import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import asyncHandler from 'express-async-handler';

const protect = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Retrieve user from database based on decoded user ID
      req.user = await User.findById(decoded.id).select('-password');

      if (!req.user) {
        throw new Error('User not found');
      }

      next();
    } catch (error) {
      console.error(error);
      res.status(401);
      next(error); // Pass error to Express error handling middleware
    }
  }

  if (!token) {
    res.status(401);
    const error = new Error('Not authorized, no token');
    next(error); // Pass error to Express error handling middleware
  }
});

const admin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(401);
    const error = new Error('Not authorized as an admin');
    next(error); // Pass error to Express error handling middleware
  }
};

export { protect, admin };
