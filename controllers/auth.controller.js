const User = require("../models/User");
const jwt = require("jsonwebtoken");

const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/ApiError");
const ApiResponse = require("../utils/ApiResponse");

const sendToken = require("../utils/sendToken");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const Session = require("../models/Session");


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

  // Find user and explicitly include password
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new ApiError(401, "Invalid email or password");
  }

  // Verify password
  const isPasswordMatched = await user.comparePassword(password);

  if (!isPasswordMatched) {
    throw new ApiError(401, "Invalid email or password");
  }

  // Generate short-lived access token
  const accessToken = jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
    }
  );

  // Generate long-lived random refresh token
  const refreshToken = crypto
    .randomBytes(64)
    .toString("hex");

  // Hash refresh token before storing it
  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  // Refresh token expires in 7 days
  const refreshTokenExpiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
  );

  // Create server-side session
  await Session.create({
    user: user._id,
    refreshTokenHash,
    expiresAt: refreshTokenExpiresAt,
  });

  // Store access token in HttpOnly cookie
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });

  // Store refresh token in HttpOnly cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.status(200).json(
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

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  // Find user
  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Generate reset token
  const resetToken = user.generatePasswordResetToken();

  // Save token and expiry
  await user.save({
    // "Skip validation this time. only save the reset token and expiry"
    validateBeforeSave: false,
  });

  // Create reset URL
  const resetUrl =
    `${req.protocol}://${req.get("host")}/api/v1/auth/reset-password/${resetToken}`;

// ------------------------------------
  console.log("Reset URL:", resetUrl);
  try {
    await sendEmail({
      email: user.email,
      subject: "Password Reset Request",
      message: `Reset your password using this link:\n\n${resetUrl}\n\nThis link expires in 15 minutes.`,
    });

    res.status(200).json(
      new ApiResponse(
        200,
        "Password reset email sent successfully"
      )
    );

  } catch (error) {

    // Rollback
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({
      validateBeforeSave: false,
    });

    throw new ApiError(
      500,
      "Email could not be sent. Please try again later."
    );
  }
});


const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;

  // Hash incoming token
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  // Find matching user
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: {
      $gt: Date.now(),
    },
  });

  if (!user) {
    throw new ApiError(400, "Reset token is invalid or has expired");
  }

  // Set new password
  user.password = password;

  // Remove reset fields
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  // Save user
  await user.save();

  res.status(200).json(
    new ApiResponse(
      200,
      "Password reset successful"
    )
  );
});


const sendVerificationEmail = asyncHandler(async (req, res) => {

    const user = await User.findById(req.user._id);

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.isVerified) {
        throw new ApiError(
            400,
            "Email is already verified"
        );
    }

    // Generate verification token
    const verificationToken =
        user.generateEmailVerificationToken();

    console.log("Verification Token:", verificationToken);
    // Save token
    await user.save({
        validateBeforeSave: false,
    });

    const verificationUrl =
        `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${verificationToken}`;

    try {

        await sendEmail({
            email: user.email,
            subject: "Verify Your Email",
            message:`Click the link below to verify your email:
                    ${verificationUrl}
                    This link expires in 24 hours.`,
        });

        res.status(200).json(
            new ApiResponse(
                200,
                "Verification email sent successfully"
            )
        );

    } catch (error) {

        // Rollback
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;

        await user.save({
            validateBeforeSave: false,
        });

        throw new ApiError(
            500,
            "Email could not be sent. Please try again later."
        );
    }

});

const verifyEmail = asyncHandler(async (req, res) => {
  // Hash the token received from the URL
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  // Find user with matching token and valid expiry
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: {
      $gt: Date.now(),
    },
  });

  if (!user) {
    throw new ApiError(
      400,
      "Verification token is invalid or has expired"
    );
  }

  // Mark email as verified
  user.isVerified = true;

  // Remove verification token
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;

  // Save changes
  await user.save();

  res.status(200).json(
    new ApiResponse(
      200,
      "Email verified successfully"
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
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
};