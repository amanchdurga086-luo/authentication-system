const express = require("express");
const authenticate =require("../middleware/auth.middleware");


const router = express.Router();

const { 
  registerUser,
   loginUser ,
   getProfile
  } = require("../controllers/auth.controller");
const { registerValidator, loginValidator } = require("../validators/auth.validator");
const validate = require("../middleware/validate.middleware");

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

module.exports = router;