const nodemailer = require("nodemailer");

const sendEmail = async ({ email, subject, message }) => {
  // Create SMTP transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // true only for port 465
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // Send email
  await transporter.sendMail({
    from: `"Authentication System" <${process.env.EMAIL_USER}>`,
    to: email,
    subject,
    text: message,
  });
};

module.exports = sendEmail;