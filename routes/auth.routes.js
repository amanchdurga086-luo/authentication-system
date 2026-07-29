const express = require("express");
const authenticate =require("../middleware/auth.middleware");


const router = express.Router();

const { 
  registerUser,
   loginUser ,
   getProfile,
    adminDashboard,
    getCurrentUser,
    logoutUser,
    changePassword,
  } = require("../controllers/auth.controller");
const {
   registerValidator,
   loginValidator,  
   changePasswordValidator, 
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

router.get(
  "/me",
  authenticate,
  getCurrentUser
);

router.post(
  "/logout",
  authenticate,
  logoutUser
);

router.put(
    "/change-password",
    authenticate,
    changePasswordValidator,
    validate,
    changePassword,
);

module.exports = router;