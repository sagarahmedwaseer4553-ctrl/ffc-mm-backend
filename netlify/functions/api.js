const serverless = require('serverless-http');
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const nodemailer = require('nodemailer');

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ── DB ────────────────────────────────────────────────────
let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true, useUnifiedTopology: true
  });
  isConnected = true;
}

// ── Schemas ───────────────────────────────────────────────
const complaintSchema = new mongoose.Schema({
  fullName:         { type: String, required: true },
  personalNumber:   { type: String, required: true },
  designation:      { type: String, required: true },
  department:       { type: String, required: true },
  mobileNumber:     { type: String, required: true },
  complaintDetails: { type: String, required: true },
  canteen:          { type: String, required: true },
  imageUrl:         { type: String, default: null },
  videoUrl:         { type: String, default: null },
  status:           { type: String, default: 'New' },
  fineAmount:       { type: Number, default: 0 },
  investigation:    { type: String, default: '' },
  remarks:          [{ text: String, addedAt: { type: Date, default: Date.now } }],
  submittedAt:      { type: Date, default: Date.now },
  updatedAt:        { type: Date },
  resolvedAt:       { type: Date }
});

const emailConfigSchema = new mongoose.Schema({
  recipients:          { type: [String], default: [] },
  enableNotifications: { type: Boolean, default: true },
  adminPinOverride:    { type: String, default: null }
});

const otpSchema = new mongoose.Schema({
  code:      { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false }
});

const subUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  pin:      { type: String, required: true, trim: true }
});

const Complaint   = mongoose.models.Complaint   || mongoose.model('Complaint',   complaintSchema);
const EmailConfig = mongoose.models.EmailConfig || mongoose.model('EmailConfig', emailConfigSchema);
const OTP         = mongoose.models.OTP         || mongoose.model('OTP',         otpSchema);
const SubUser     = mongoose.models.SubUser     || mongoose.model('SubUser',     subUserSchema);

// ── Email ─────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD }
});

// ── DB middleware ─────────────────────────────────────────
app.use(async (req, res, next) => {
  try { await connectDB(); next(); }
  catch (e) { res.status(500).json({ error: 'Database connection failed' }); }
});

// ── Constants ─────────────────────────────────────────────
// These are hardcoded — never rely on env for superadmin credentials
const PERMANENT_USER = 'kingsman';
const PERMANENT_PIN  = '1920';
const ADMIN_EMAIL    = 'sagarahmedwaseer4553@gmail.com';

/*
 * THE CORE AUTH FUNCTION
 * Accepts a single PIN and checks ALL valid sources.
 * No username required for header-based dashboard auth.
 * Username only used for login to determine super-admin status.
 */
async function isPinValid(pin) {
  const p = String(pin || '').trim();
  if (!p) return false;

  // 1. Kingsman permanent PIN
  if (p === PERMANENT_PIN) return true;

  // 2. Env ADMIN_PIN (legacy)
  const envPin = String(process.env.ADMIN_PIN || '').trim();
  if (envPin && p === envPin) return true;

  // 3. DB override PIN (set via forgot-pin)
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim()) return true;
  } catch (e) { /* ignore */ }

  // 4. Sub-user PIN (any sub-user's PIN works for dashboard access)
  try {
    const sub = await SubUser.findOne({ pin: p });
    if (sub) return true;
  } catch (e) { /* ignore */ }

  return false;
}

/*
 * LOGIN VERIFICATION
 * Returns { valid, isSuperAdmin }
 * Checks username+pin combo to determine role.
 */
async function verifyLogin(pin, username) {
  const p = String(pin || '').trim();
  const u = String(username || '').trim().toLowerCase();

  if (!p || !u) return { valid: false, isSuperAdmin: false };

  // Permanent superadmin
  if (u === PERMANENT_USER && p === PERMANENT_PIN) {
    return { valid: true, isSuperAdmin: true };
  }

  // Env ADMIN_PIN (legacy — treated as superadmin)
  const envPin = String(process.env.ADMIN_PIN || '').trim();
  if (envPin && p === envPin) {
    return { valid: true, isSuperAdmin: true };
  }

  // DB override PIN
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim()) {
      return { valid: true, isSuperAdmin: false };
    }
  } catch (e) { /* ignore */ }

  // Sub-user: username AND pin must match
  try {
    const sub = await SubUser.findOne({ username: u, pin: p });
    if (sub) return { valid: true, isSuperAdmin: false };
  } catch (e) { /* ignore */ }

  return { valid: false, isSuperAdmin: false };
}

// Get PIN from request headers (any casing)
function getHeaderPin(req) {
  return req.headers['adminpin'] ||
         req.headers['adminPin'] ||
         req.headers['admin-pin'] ||
         req.headers['Admin-Pin'] || '';
}

// ══════════════════════════════════════════════════════════
// HEALTH
// ══════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server running ✅', timestamp: new Date().toISOString() });
});

// ══════════════════════════════════════════════════════════
// COMPLAINTS — public read, pin-protected write
// ══════════════════════════════════════════════════════════
app.post('/api/complaints', async (req, res) => {
  try {
    const { fullName, personalNumber, designation, department,
            mobileNumber, complaintDetails, canteen, imageUrl, videoUrl } = req.body;

    if (!fullName || !personalNumber || !designation || !department ||
        !mobileNumber || !complaintDetails || !canteen)
      return res.status(400).json({ error: 'Missing required fields' });

    const complaint = await new Complaint({
      fullName, personalNumber, designation, department,
      mobileNumber, complaintDetails, canteen,
      imageUrl: imageUrl || null,
      videoUrl: videoUrl || null,
      status: 'New',
      submittedAt: new Date()
    }).save();

    sendComplaintNotification(complaint);
    res.status(201).json({
      success: true,
      message: 'Complaint submitted successfully',
      complaintId: complaint._id
    });
  } catch (e) {
    console.error('Submit error:', e);
    res.status(500).json({ error: 'Error submitting complaint' });
  }
});

app.get('/api/complaints', async (req, res) => {
  try {
    const { canteen, status, searchTerm } = req.query;
    let query = {};
    if (canteen)    query.canteen = canteen;
    if (status)     query.status  = status;
    if (searchTerm) query.$or = [
      { fullName:         new RegExp(searchTerm, 'i') },
      { personalNumber:   new RegExp(searchTerm, 'i') },
      { complaintDetails: new RegExp(searchTerm, 'i') }
    ];
    res.json(await Complaint.find(query).sort({ submittedAt: -1 }));
  } catch (e) { res.status(500).json({ error: 'Error fetching complaints' }); }
});

app.get('/api/complaints/:id', async (req, res) => {
  try {
    const c = await Complaint.findById(req.params.id);
    if (!c) return res.status(404).json({ error: 'Not found' });
    res.json(c);
  } catch (e) { res.status(500).json({ error: 'Error fetching complaint' }); }
});

app.put('/api/complaints/:id', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized' });

    const { status, remarks, fineAmount, investigation } = req.body;
    const update = { updatedAt: new Date() };
    if (status !== undefined)        update.status        = status;
    if (fineAmount !== undefined)    update.fineAmount    = fineAmount;
    if (investigation !== undefined) update.investigation = investigation;
    if (status === 'Resolved')       update.resolvedAt    = new Date();

    const complaint = await Complaint.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!complaint) return res.status(404).json({ error: 'Not found' });

    if (remarks) {
      complaint.remarks.push({ text: remarks, addedAt: new Date() });
      await complaint.save();
    }
    sendUpdateNotification(complaint);
    res.json({ success: true, complaint });
  } catch (e) { res.status(500).json({ error: 'Error updating complaint' }); }
});

app.delete('/api/complaints/:id', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized' });
    await Complaint.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Complaint deleted' });
  } catch (e) { res.status(500).json({ error: 'Error deleting complaint' }); }
});

// ══════════════════════════════════════════════════════════
// ADMIN LOGIN
// ══════════════════════════════════════════════════════════
app.post('/api/admin/verify-pin', async (req, res) => {
  try {
    const { pin, username } = req.body;
    console.log(`Login attempt — user:"${username}" pin:"${pin}"`);

    const result = await verifyLogin(pin, username);
    console.log(`Login result:`, result);

    if (result.valid) {
      res.json({ success: true, isSuperAdmin: result.isSuperAdmin });
    } else {
      res.status(401).json({ error: 'Invalid username or PIN' });
    }
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login error: ' + e.message });
  }
});

// ══════════════════════════════════════════════════════════
// ADMIN STATS
// ══════════════════════════════════════════════════════════
app.get('/api/admin/stats', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized' });

    const [total, newC, inProg, resolved, byCanteen] = await Promise.all([
      Complaint.countDocuments(),
      Complaint.countDocuments({ status: 'New' }),
      Complaint.countDocuments({ status: 'In Progress' }),
      Complaint.countDocuments({ status: 'Resolved' }),
      Complaint.aggregate([{ $group: { _id: '$canteen', count: { $sum: 1 } } }])
    ]);
    res.json({
      totalComplaints:       total,
      newComplaints:         newC,
      inProgressComplaints:  inProg,
      resolvedComplaints:    resolved,
      byCanteen
    });
  } catch (e) { res.status(500).json({ error: 'Error fetching stats' }); }
});

// ══════════════════════════════════════════════════════════
// EMAIL CONFIG
// ══════════════════════════════════════════════════════════
app.get('/api/admin/email-config', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized' });
    let config = await EmailConfig.findOne();
    if (!config) config = await new EmailConfig({ recipients: [], enableNotifications: true }).save();
    res.json(config);
  } catch (e) { res.status(500).json({ error: 'Error fetching email config' }); }
});

app.put('/api/admin/email-config', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized' });
    const { recipients, enableNotifications } = req.body;
    let config = await EmailConfig.findOne() || new EmailConfig();
    if (recipients !== undefined)          config.recipients          = recipients;
    if (enableNotifications !== undefined) config.enableNotifications = enableNotifications;
    await config.save();
    res.json({ success: true, config });
  } catch (e) { res.status(500).json({ error: 'Error updating email config' }); }
});

// ══════════════════════════════════════════════════════════
// SUB-USER MANAGEMENT
// ══════════════════════════════════════════════════════════
app.get('/api/admin/users', async (req, res) => {
  try {
    const { pin, username } = req.query;
    const result = await verifyLogin(pin, username);
    if (!result.valid || !result.isSuperAdmin)
      return res.status(401).json({ error: 'Superadmin only' });
    const users = await SubUser.find({}, { pin: 0 });
    res.json(users);
  } catch (e) { res.status(500).json({ error: 'Error fetching users' }); }
});

app.post('/api/admin/users', async (req, res) => {
  try {
    const { pin, username, newUsername, newPin } = req.body;
    const result = await verifyLogin(pin, username);
    if (!result.valid || !result.isSuperAdmin)
      return res.status(401).json({ error: 'Superadmin only' });

    if (!newUsername || !newPin)
      return res.status(400).json({ error: 'Username and PIN required' });
    if (String(newPin).length < 4)
      return res.status(400).json({ error: 'PIN must be at least 4 digits' });
    if (String(newUsername).trim().toLowerCase() === PERMANENT_USER)
      return res.status(400).json({ error: 'Cannot use reserved username' });

    const exists = await SubUser.findOne({ username: String(newUsername).trim().toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Username already exists' });

    await new SubUser({
      username: String(newUsername).trim().toLowerCase(),
      pin:      String(newPin).trim()
    }).save();

    res.json({ success: true, message: `User "${newUsername}" added` });
  } catch (e) {
    console.error('Add user error:', e);
    res.status(500).json({ error: 'Error adding user' });
  }
});

app.delete('/api/admin/users/:target', async (req, res) => {
  try {
    const { pin, username } = req.body;
    const result = await verifyLogin(pin, username);
    if (!result.valid || !result.isSuperAdmin)
      return res.status(401).json({ error: 'Superadmin only' });
    await SubUser.findOneAndDelete({ username: req.params.target.toLowerCase() });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Error removing user' }); }
});

// ══════════════════════════════════════════════════════════
// OTP / FORGOT PIN / RESET PIN
// ══════════════════════════════════════════════════════════
async function generateAndSendOtp() {
  await OTP.deleteMany({});
  const code      = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await new OTP({ code, expiresAt }).save();
  await transporter.sendMail({
    from:    process.env.EMAIL_USER,
    to:      ADMIN_EMAIL,
    subject: '🔐 FFC MM — Verification Code',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:28px;
                  border:1px solid #ddd;border-radius:10px">
        <h2 style="color:#a83030;margin:0 0 8px">FFC MM Canteens</h2>
        <p style="color:#444;margin:0 0 24px">Your one-time verification code:</p>
        <div style="background:#fdf3dc;border:2px solid #c8960a;border-radius:8px;
                    padding:24px;text-align:center;margin-bottom:24px">
          <span style="font-size:40px;font-weight:bold;letter-spacing:12px;color:#a83030">
            ${code}
          </span>
        </div>
        <p style="color:#888;font-size:13px;margin:0">Expires in <strong>10 minutes</strong>.</p>
      </div>`
  });
  return true;
}

app.post('/api/admin/forgot-pin', async (req, res) => {
  try {
    await generateAndSendOtp();
    res.json({ success: true, message: `Code sent to ${ADMIN_EMAIL}` });
  } catch (e) {
    console.error('OTP error:', e);
    res.status(500).json({ error: 'Failed to send code. Check EMAIL_USER and EMAIL_PASSWORD env vars.' });
  }
});

app.post('/api/admin/verify-otp', async (req, res) => {
  try {
    const { otp } = req.body;
    const record  = await OTP.findOne({ code: String(otp).trim(), used: false });
    if (!record)                       return res.status(400).json({ error: 'Invalid code' });
    if (new Date() > record.expiresAt) return res.status(400).json({ error: 'Code expired' });
    record.used = true;
    await record.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Error verifying OTP' }); }
});

app.post('/api/admin/reset-pin', async (req, res) => {
  try {
    const { otp, newPin } = req.body;
    if (!otp || !newPin)           return res.status(400).json({ error: 'OTP and new PIN required' });
    if (String(newPin).length < 4) return res.status(400).json({ error: 'PIN must be 4+ digits' });

    const record = await OTP.findOne({ code: String(otp).trim(), used: false });
    if (!record)                       return res.status(400).json({ error: 'Invalid code' });
    if (new Date() > record.expiresAt) return res.status(400).json({ error: 'Code expired' });
    record.used = true;
    await record.save();

    let config = await EmailConfig.findOne() || new EmailConfig();
    config.adminPinOverride = String(newPin).trim();
    await config.save();

    res.json({ success: true, message: 'PIN updated! Use your new PIN to login.' });
  } catch (e) {
    console.error('Reset PIN error:', e);
    res.status(500).json({ error: 'Error resetting PIN' });
  }
});

// ══════════════════════════════════════════════════════════
// EMAIL HELPERS
// ══════════════════════════════════════════════════════════
async function sendComplaintNotification(complaint) {
  try {
    const config = await EmailConfig.findOne();
    if (!config || !config.enableNotifications || !config.recipients.length) return;
    await transporter.sendMail({
      from:    process.env.EMAIL_USER,
      to:      config.recipients.join(', '),
      subject: `🔔 New Complaint — ${complaint.canteen}`,
      html: `<h2>New Complaint Received</h2>
             <p><strong>Canteen:</strong> ${complaint.canteen}</p>
             <p><strong>Name:</strong> ${complaint.fullName}</p>
             <p><strong>P. No:</strong> ${complaint.personalNumber}</p>
             <p><strong>Department:</strong> ${complaint.department}</p>
             <p><strong>Mobile:</strong> ${complaint.mobileNumber}</p>
             <p><strong>Complaint:</strong><br>${complaint.complaintDetails}</p>
             <p><strong>Status:</strong> ${complaint.status}</p>
             <p>ID: ${complaint._id}</p>`
    });
  } catch (e) { console.error('Notification error:', e); }
}

async function sendUpdateNotification(complaint) {
  try {
    if (!complaint.mobileNumber.includes('@')) return;
    await transporter.sendMail({
      from:    process.env.EMAIL_USER,
      to:      complaint.mobileNumber,
      subject: `📋 Complaint Update — ${complaint.canteen}`,
      html: `<h2>Status Update</h2>
             <p><strong>Status:</strong> ${complaint.status}</p>
             <p><strong>Fine:</strong> ${complaint.fineAmount || 'N/A'}</p>
             <p><strong>Investigation:</strong> ${complaint.investigation || 'In progress'}</p>`
    });
  } catch (e) { console.error('Update email error:', e); }
}

module.exports.handler = serverless(app);
