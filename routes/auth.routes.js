const express = require("express");
const authenticate =require("../middleware/auth.middleware");


const router = express.Router();

const { 
  registerUser,
  loginUser ,
  getProfile,
  adminDashboard,
  logoutUser,
  changePassword,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
  refreshAccessToken,
  logoutAllDevices,
  } = require("../controllers/auth.controller");

const {
   registerValidator,
   loginValidator,  
   changePasswordValidator, 
   forgotPasswordValidator,
   resetPasswordValidator,
  } = require("../validators/auth.validator");

const validate = require("../middleware/validate.middleware");
const authorize = require("../middleware/authorize.middleware");

router.post(
  "/register",
  registerValidator,
  validate,
  registerUser
);

router.post(
    "/login",
    loginValidator,
    validate,
    loginUser
);

router.get(
    "/profile",
    authenticate,
    getProfile
);

router.get(
    "/admin",
    authenticate,
    authorize("admin"),
    adminDashboard
);


router.post(
  "/logout",
  logoutUser
);


router.put(
    "/change-password",
    authenticate,
    changePasswordValidator,
    validate,
    changePassword,
);

router.post(
  "/forgot-password",
  forgotPasswordValidator,
  validate,
  forgotPassword
);

router.put(
  "/reset-password/:token",
  resetPasswordValidator,
  validate,
  resetPassword
);

router.post(
  "/send-verification-email",
  authenticate,  // we get user id from it that we need to send email verification link
  sendVerificationEmail
);

router.get(
  "/verify-email/:token",
  verifyEmail
);

router.post(
  "/refresh-token",
  refreshAccessToken
);

router.post(
  "/logout-all",
  authenticate,
  logoutAllDevices
);

module.exports = router;