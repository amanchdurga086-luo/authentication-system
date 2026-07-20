const express = require("express");

const router = express.Router();

const { registerUser } = require("../controllers/auth.controller");
const { registerValidator } = require("../validators/auth.validator");
const validate = require("../middleware/validate.middleware");

router.post(
  "/register",
  registerValidator,
  validate,
  registerUser
);

module.exports = router;