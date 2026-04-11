const mongoose = require('mongoose');

const EmailConfigSchema = new mongoose.Schema({
  recipients:          { type: [String], default: [] },
  enableNotifications: { type: Boolean,  default: true },
  adminPinOverride:    { type: String,    default: null }
});

module.exports = mongoose.models.EmailConfig ||
                 mongoose.model('EmailConfig', EmailConfigSchema);
