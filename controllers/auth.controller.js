const User = require("../models/User");
const jwt = require("jsonwebtoken");

const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/ApiError");
const ApiResponse = require("../utils/ApiResponse");

const sendToken = require("../utils/sendToken");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const Session = require("../models/Session");
const RefreshToken = require("../models/RefreshToken");
const mongoose = require("mongoose");


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
    throw new ApiError(
      401,
      "Invalid email or password"
    );
  }

  // Compare password
  const isPasswordMatched =
    await user.comparePassword(password);

  if (!isPasswordMatched) {
    throw new ApiError(
      401,
      "Invalid email or password"
    );
  }

  // Generate access token
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

  // Generate refresh token
  const refreshToken = crypto
    .randomBytes(64)
    .toString("hex");

  // Hash refresh token
  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  // Create token family
  const tokenFamily = crypto.randomUUID();

  // Refresh token expiry
  const refreshTokenExpiresAt = new Date(
    Date.now() +
      7 * 24 * 60 * 60 * 1000
  );

  // Create session
  const session = await Session.create({
    user: user._id,
    tokenFamily,
    expiresAt: refreshTokenExpiresAt,
  });

  // Store refresh token record in refresh token collection
  await RefreshToken.create({
    session: session._id,
    tokenHash: refreshTokenHash,
    tokenFamily,
    expiresAt: refreshTokenExpiresAt,
  });

  // Access token cookie
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure:
      process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });

  // Refresh token cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure:
      process.env.NODE_ENV === "production",
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

const logoutUser = asyncHandler(
  async (req, res) => {
    const refreshToken =
      req.cookies.refreshToken;

    if (refreshToken) {
      const tokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

      const tokenRecord =
        await RefreshToken.findOne({
          tokenHash,
        });

      if (tokenRecord) {
        const session =
          await Session.findById(
            tokenRecord.session
          );

        if (session && !session.revokedAt) {
          session.revokedAt = new Date();

          await session.save();
        }
      }
    }

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure:
        process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure:
        process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json(
      new ApiResponse(
        200,
        "Logout successful"
      )
    );
  }
);

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


const refreshAccessToken = asyncHandler(
  async (req, res) => {
    const refreshToken =
      req.cookies.refreshToken;

    if (!refreshToken) {
      throw new ApiError(
        401,
        "Refresh token is required"
      );
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const dbSession =
      await mongoose.startSession();

    try {
      dbSession.startTransaction();

      // Atomically consume the refresh token
      const now = new Date();

      const tokenRecord =
        await RefreshToken.findOneAndUpdate(
          {
            tokenHash,
            //this condition what prevents double consumption.
            usedAt: null,
            revokedAt: null,
            expiresAt: {
              $gt: now,
            },
          },
          {
            $set: {
              usedAt: now,
            },
          },
          {
            new: true,
            session: dbSession,
          }
        );

      if (!tokenRecord) {
        const existingToken =
          await RefreshToken.findOne({
            tokenHash,
          }).session(dbSession);

        if (existingToken?.usedAt) {
          const compromisedSession =
            await Session.findById(
              existingToken.session
            ).session(dbSession);

          if (compromisedSession) {
            compromisedSession.revokedAt =
              new Date();

            await compromisedSession.save({
              session: dbSession,
            });

            console.warn(
              "Refresh token reuse detected",
              {
                sessionId:
                  compromisedSession._id,
                userId:
                  compromisedSession.user,
                tokenFamily:
                  existingToken.tokenFamily,
              }
            );
          }
        }

        throw new ApiError(
          401,
          "Invalid refresh token"
        );
      }

      // Find the associated application session
      const session =
        await Session.findById(
          tokenRecord.session
        ).session(dbSession);

      if (!session) {
        throw new ApiError(
          401,
          "Session not found"
        );
      }

      // Check session revocation
      if (session.revokedAt) {
        throw new ApiError(
          401,
          "Session has been revoked"
        );
      }

      // Check session expiration
      if (session.expiresAt <= new Date()) {
        throw new ApiError(
          401,
          "Session has expired"
        );
      }

      // Find user
      const user = await User.findById(
        session.user
      ).session(dbSession);

      if (!user) {
        throw new ApiError(
          401,
          "User associated with session no longer exists"
        );
      }

      // Generate new refresh token
      const newRefreshToken =
        crypto.randomBytes(64).toString("hex");

      // Hash new refresh token
      const newTokenHash = crypto
        .createHash("sha256")
        .update(newRefreshToken)
        .digest("hex");

      // Create new refresh-token record
      await RefreshToken.create(
        [
          {
            session: session._id,
            tokenHash: newTokenHash,
            tokenFamily: session.tokenFamily,
            expiresAt: session.expiresAt,
          },
        ],
        {
          session: dbSession,
        }
      );

      // Generate new access token
      const accessToken = jwt.sign(
        {
          id: user._id,
          role: user.role,
        },
        process.env.JWT_SECRET,
        {
          expiresIn:
            process.env.ACCESS_TOKEN_EXPIRES_IN,
        }
      );

      // Commit database changes
      await dbSession.commitTransaction();

      // Set new access token cookie
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure:
          process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 15 * 60 * 1000,
      });

      // Set new refresh token cookie
      res.cookie(
        "refreshToken",
        newRefreshToken,
        {
          httpOnly: true,
          secure:
            process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge:
            7 * 24 * 60 * 60 * 1000,
        }
      );

      res.status(200).json(
        new ApiResponse(
          200,
          "Tokens refreshed successfully"
        )
      );
    } catch (error) {
      await dbSession.abortTransaction();

      throw error;
    } finally {
      await dbSession.endSession();
    }
  }
);

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
  refreshAccessToken,
};