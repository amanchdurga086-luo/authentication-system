const express = require("express");
const authenticate =require("../middleware/auth.middleware");


const router = express.Router();

const { 
  registerUser,
   loginUser ,
   getProfile,
    adminDashboard
  } = require("../controllers/auth.controller");
const { registerValidator, loginValidator } = require("../validators/auth.validator");
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

module.exports = router;