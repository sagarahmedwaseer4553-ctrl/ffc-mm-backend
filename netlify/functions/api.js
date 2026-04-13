const serverless = require('serverless-http');
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const nodemailer = require('nodemailer');

const app = express();

// ── CORS — allow all origins so it never blocks ───────────
app.use(cors({
  origin: true,          // reflect whatever origin sends the request
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: [
    'Content-Type','Authorization',
    'adminpin','AdminPin','admin-pin','Admin-Pin'
  ]
}));
app.options('*', cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ── DB ────────────────────────────────────────────────────
let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGODB_URI);
  isConnected = true;
  console.log('✅ MongoDB connected');
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
  adminPinOverride:    { type: String,   default: null }
});

const otpSchema = new mongoose.Schema({
  code:      { type: String,  required: true },
  expiresAt: { type: Date,    required: true },
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
  catch (e) {
    console.error('DB error:', e.message);
    res.status(500).json({ error: 'Database connection failed: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
// CONSTANTS
// CRITICAL FIX: Superadmin credentials are hardcoded here.
// They do NOT depend on env vars, so they can never be wrong.
// ════════════════════════════════════════════════════════
const SUPERADMIN_USER = 'kingsman';
const SUPERADMIN_PIN  = '1920';          // ← THE FIX: was '1914' before
const ADMIN_EMAIL     = 'sagarahmedwaseer4553@gmail.com';

// ── Auth helpers ──────────────────────────────────────────

/*
 * isPinValid(pin)
 * Checks a PIN against ALL valid sources:
 *   1. Superadmin PIN (hardcoded '1920')
 *   2. DB override PIN (set via forgot-pin)
 *   3. Any sub-user's PIN
 * Used for header-based dashboard auth (no username needed).
 */
async function isPinValid(pin) {
  const p = String(pin || '').trim();
  if (!p) return false;

  // 1. Superadmin PIN
  if (p === SUPERADMIN_PIN) return true;

  // 2. DB override PIN
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim()) return true;
  } catch (e) { /* ignore */ }

  // 3. Any sub-user PIN
  try {
    const sub = await SubUser.findOne({ pin: p });
    if (sub) return true;
  } catch (e) { /* ignore */ }

  return false;
}

/*
 * verifyLogin(pin, username)
 * Full login verification — checks username+pin combo.
 * Returns { valid: bool, isSuperAdmin: bool }
 */
async function verifyLogin(pin, username) {
  const p = String(pin     || '').trim();
  const u = String(username || '').trim().toLowerCase();
  if (!p || !u) return { valid: false, isSuperAdmin: false };

  // Superadmin
  if (u === SUPERADMIN_USER && p === SUPERADMIN_PIN) {
    return { valid: true, isSuperAdmin: true };
  }

  // DB override PIN — treat as superadmin if username is also kingsman
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim()) {
      return { valid: true, isSuperAdmin: u === SUPERADMIN_USER };
    }
  } catch (e) { /* ignore */ }

  // Sub-user: both username AND pin must match
  try {
    const sub = await SubUser.findOne({ username: u, pin: p });
    if (sub) return { valid: true, isSuperAdmin: false };
  } catch (e) { /* ignore */ }

  return { valid: false, isSuperAdmin: false };
}

function getHeaderPin(req) {
  return req.headers['adminpin'] ||
         req.headers['adminPin'] ||
         req.headers['admin-pin'] ||
         req.headers['Admin-Pin'] || '';
}

// ════════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server running ✅', timestamp: new Date().toISOString() });
});

// ════════════════════════════════════════════════════════
// COMPLAINTS
// ════════════════════════════════════════════════════════
app.post('/api/complaints', async (req, res) => {
  try {
    const {
      fullName, personalNumber, designation, department,
      mobileNumber, complaintDetails, canteen, imageUrl, videoUrl
    } = req.body;

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

    // Fire-and-forget email — never block the response
    sendComplaintNotification(complaint).catch(e =>
      console.error('Notification email error:', e.message)
    );

    res.status(201).json({
      success: true,
      message: 'Complaint submitted successfully',
      complaintId: complaint._id
    });
  } catch (e) {
    console.error('Submit error:', e);
    res.status(500).json({ error: 'Error submitting complaint: ' + e.message });
  }
});

app.get('/api/complaints', async (req, res) => {
  try {
    const { canteen, status, searchTerm } = req.query;
    const query = {};
    if (canteen)    query.canteen = canteen;
    if (status)     query.status  = status;
    if (searchTerm) query.$or = [
      { fullName:         new RegExp(searchTerm, 'i') },
      { personalNumber:   new RegExp(searchTerm, 'i') },
      { complaintDetails: new RegExp(searchTerm, 'i') }
    ];
    res.json(await Complaint.find(query).sort({ submittedAt: -1 }));
  } catch (e) {
    console.error('Fetch complaints error:', e);
    res.status(500).json({ error: 'Error fetching complaints: ' + e.message });
  }
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
    console.log(`PUT /complaints — pin received: "${pin}"`);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized — invalid PIN' });

    const { status, remarks, fineAmount, investigation } = req.body;
    const update = { updatedAt: new Date() };
    if (status !== undefined)        update.status        = status;
    if (fineAmount !== undefined)    update.fineAmount    = parseFloat(fineAmount) || 0;
    if (investigation !== undefined) update.investigation = investigation;
    if (status === 'Resolved')       update.resolvedAt    = new Date();

    const complaint = await Complaint.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!complaint) return res.status(404).json({ error: 'Not found' });

    if (remarks && String(remarks).trim()) {
      complaint.remarks.push({ text: String(remarks).trim(), addedAt: new Date() });
      await complaint.save();
    }

    sendUpdateNotification(complaint).catch(e =>
      console.error('Update email error:', e.message)
    );
    res.json({ success: true, complaint });
  } catch (e) {
    console.error('Update complaint error:', e);
    res.status(500).json({ error: 'Error updating complaint: ' + e.message });
  }
});

app.delete('/api/complaints/:id', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized — invalid PIN' });
    await Complaint.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Complaint deleted' });
  } catch (e) { res.status(500).json({ error: 'Error deleting complaint' }); }
});

// ════════════════════════════════════════════════════════
// ADMIN LOGIN
// ════════════════════════════════════════════════════════
app.post('/api/admin/verify-pin', async (req, res) => {
  try {
    const { pin, username } = req.body;
    console.log(`Login attempt — user:"${username}" pin length:${String(pin||'').length}`);

    const result = await verifyLogin(pin, username);
    console.log(`Login result: valid=${result.valid} superAdmin=${result.isSuperAdmin}`);

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

// ════════════════════════════════════════════════════════
// ADMIN STATS
// ════════════════════════════════════════════════════════
app.get('/api/admin/stats', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    console.log(`GET /admin/stats — pin: "${pin}"`);
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
      totalComplaints:      total,
      newComplaints:        newC,
      inProgressComplaints: inProg,
      resolvedComplaints:   resolved,
      byCanteen
    });
  } catch (e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: 'Error fetching stats: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
// EMAIL CONFIG
// ════════════════════════════════════════════════════════
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

// ════════════════════════════════════════════════════════
// SUB-USER MANAGEMENT
// ════════════════════════════════════════════════════════
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
    if (String(newUsername).trim().toLowerCase() === SUPERADMIN_USER)
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
    res.status(500).json({ error: 'Error adding user: ' + e.message });
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

// ════════════════════════════════════════════════════════
// OTP / FORGOT PIN / RESET PIN
// ════════════════════════════════════════════════════════
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
      <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;
                  padding:28px;border:1px solid #ddd;border-radius:10px">
        <h2 style="color:#a83030;margin:0 0 8px">FFC MM Canteens</h2>
        <p style="color:#444;margin:0 0 24px">Your one-time verification code:</p>
        <div style="background:#fdf3dc;border:2px solid #c8960a;border-radius:8px;
                    padding:24px;text-align:center;margin-bottom:24px">
          <span style="font-size:40px;font-weight:bold;letter-spacing:12px;color:#a83030">
            ${code}
          </span>
        </div>
        <p style="color:#888;font-size:13px;margin:0">
          Expires in <strong>10 minutes</strong>.
        </p>
      </div>`
  });
  return true;
}

app.post('/api/admin/forgot-pin', async (req, res) => {
  try {
    await generateAndSendOtp();
    res.json({ success: true, message: `Code sent to ${ADMIN_EMAIL}` });
  } catch (e) {
    console.error('OTP send error:', e);
    res.status(500).json({
      error: 'Failed to send code. Check EMAIL_USER / EMAIL_PASSWORD env vars. Error: ' + e.message
    });
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
    res.status(500).json({ error: 'Error resetting PIN: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
// EMAIL HELPERS
// ════════════════════════════════════════════════════════
async function sendComplaintNotification(complaint) {
  const config = await EmailConfig.findOne();
  if (!config || !config.enableNotifications || !config.recipients || !config.recipients.length) return;
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
           <p><strong>Complaint:</strong><br>${complaint.complaintDetails.replace(/\n/g, '<br>')}</p>
           <p><strong>Status:</strong> ${complaint.status}</p>
           <p><strong>ID:</strong> ${complaint._id}</p>`
  });
}

async function sendUpdateNotification(complaint) {
  if (!complaint.mobileNumber || !complaint.mobileNumber.includes('@')) return;
  await transporter.sendMail({
    from:    process.env.EMAIL_USER,
    to:      complaint.mobileNumber,
    subject: `📋 Complaint Update — ${complaint.canteen}`,
    html: `<h2>Status Update</h2>
           <p><strong>Status:</strong> ${complaint.status}</p>
           <p><strong>Fine:</strong> ${complaint.fineAmount || 'N/A'}</p>
           <p><strong>Investigation:</strong> ${complaint.investigation || 'In progress'}</p>`
  });
}

module.exports.handler = serverless(app);
