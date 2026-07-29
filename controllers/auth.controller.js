const User = require("../models/User");
const jwt = require("jsonwebtoken");

const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/ApiError");
const ApiResponse = require("../utils/ApiResponse");
const sendToken = require("../utils/sendToken");


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

  // generate token and send response
  sendToken(
    user,
    200,
    res,
    "Login successful"
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


const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Fetch user with password
    const user = await User.findById(req.user._id).select("+password");

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    // Verify old password
    const isMatch = await user.comparePassword(oldPassword);

    if (!isMatch) {
        throw new ApiError(401, "Old password is incorrect");
    }

    // Update password
    user.password = newPassword;

    // Triggers pre("save") middleware and hashes the password
    await user.save();

    res.status(200).json(
        new ApiResponse(
            200,
            "Password changed successfully"
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
  changePassword,
};