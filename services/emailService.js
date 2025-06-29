const nodemailer = require('nodemailer');
const logger = require('../middlewares/logger');
const { EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS } = require('../utils/constants');

// Create a transporter
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// Verify transporter
transporter.verify((error) => {
  if (error) {
    logger.error(`Email transporter error: ${error}`);
  } else {
    logger.info('Email server is ready to take our messages');
  }
});

// Send email
const sendEmail = async (options) => {
  try {
    const message = {
      from: `"vChat" <${EMAIL_USER}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html || `<p>${options.message}</p>`,
    };

    await transporter.sendMail(message);
  } catch (error) {
    logger.error(`Email send error: ${error.message}`);
    throw error;
  }
};

module.exports = { sendEmail };
