// models/EmailConfig.js
const mongoose = require('mongoose');

const emailConfigSchema = new mongoose.Schema({
  recipients: [
    {
      type: String,
      validate: {
        validator: function(v) {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
        },
        message: 'Invalid email address'
      }
    }
  ],
  enableNotifications: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('EmailConfig', emailConfigSchema);
