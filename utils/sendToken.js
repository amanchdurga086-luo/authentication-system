const jwt = require("jsonwebtoken");
const ApiResponse = require("./ApiResponse");

const sendToken = (user, statusCode, res, message) => {
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

  // Set Cookie
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  // Send Response
  return res.status(statusCode).json(
    new ApiResponse(
      statusCode,
      message,
      {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      }
    )
  );
};

module.exports = sendToken;