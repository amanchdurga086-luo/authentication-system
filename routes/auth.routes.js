const express = require("express");

const router = express.Router();

const { registerUser, loginUser } = require("../controllers/auth.controller");
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

module.exports = router;