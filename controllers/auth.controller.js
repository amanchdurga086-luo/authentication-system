const User = require("../models/User");
const jwt = require("jsonwebtoken");

const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/ApiError");
const ApiResponse = require("../utils/ApiResponse");


const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Check if email already exists
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    throw new ApiError(409, "Email already registered");
  }

  // Create user
  const user = await User.create({
    name,
    email,
    password,
  });

  res.status(201).json(
    new ApiResponse(
    201,
    "User registered successfully",
    {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
    },
  ));
});


const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user with password
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new ApiError(401, "Invalid email or password");
  }

  // Compare password
  const isMatched = await user.comparePassword(password);

  if (!isMatched) {
    throw new ApiError(401, "Invalid email or password");
  }

  // Generate JWT
  const token = jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );

  // Send JWT in Cookie
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res
  .status(200)
  .json(
    new ApiResponse(
      200,
      "Login successful",
      {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    )
  );
});


const getProfile = asyncHandler(async (req, res) => {
  res.status(200).json(
    new ApiResponse(
    200,
    "Current user fetched successfully",
    {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      isVerified: req.user.isVerified,
      createdAt: req.user.createdAt,
    },
  ));
});



const adminDashboard = asyncHandler(async (req, res) => {
  res.status(200).json(
    new ApiResponse(
    200,
    "Admin dashboard accessed successfully",
  ));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  res.status(200).json(
    new ApiResponse(
    200,
    "Current user fetched successfully",
    {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      isVerified: req.user.isVerified,
      createdAt: req.user.createdAt,
    },
  ));
});

const logoutUser = asyncHandler(async (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  res.status(200).json(
    new ApiResponse(
      200,
      "Logged out successfully"
    )
  );
});



module.exports = {
  registerUser,
  loginUser,
  getProfile,
  getCurrentUser,
  adminDashboard,
  logoutUser,
};