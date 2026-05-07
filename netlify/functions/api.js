const serverless = require('serverless-http');
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const nodemailer = require('nodemailer');

const app = express();

// ── CORS ──────────────────────────────────────────────────
app.use(cors({
  origin: true,
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

// ── Menu Schema ───────────────────────────────────────────
// Stores the entire menu as a single JSON document per canteen.
// canteen: 'Plant Canteen' | 'Staff Hostel-II Canteen' | 'Cafeteria Canteen'
const menuSchema = new mongoose.Schema({
  canteen:  { type: String, required: true, unique: true },
  days:     { type: mongoose.Schema.Types.Mixed, default: [] }, // array of day objects
  contacts: { type: mongoose.Schema.Types.Mixed, default: [] }, // [[name, number], ...]
  updatedAt:{ type: Date, default: Date.now }
});

const Complaint   = mongoose.models.Complaint   || mongoose.model('Complaint',   complaintSchema);
const EmailConfig = mongoose.models.EmailConfig || mongoose.model('EmailConfig', emailConfigSchema);
const OTP         = mongoose.models.OTP         || mongoose.model('OTP',         otpSchema);
const SubUser     = mongoose.models.SubUser     || mongoose.model('SubUser',     subUserSchema);
const Menu        = mongoose.models.Menu        || mongoose.model('Menu',        menuSchema);

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

// ── Constants ─────────────────────────────────────────────
const SUPERADMIN_USER = 'kingsman';
const SUPERADMIN_PIN  = '1920';
const ADMIN_EMAIL     = 'sagarahmedwaseer4553@gmail.com';

const CANTEEN_NAMES = ['Plant Canteen', 'Staff Hostel-II Canteen', 'Cafeteria Canteen'];

// Default menu data used when no DB record exists yet
const DEFAULT_MENU_DATA = {
  'Plant Canteen': [
    { day:'Monday',    tag:'Start of Week',    meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Egg','Aloo Bhujia','Milk','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Chicken Biryani','Mix Vegetables','Dal Lobia']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Mutton Qorma','Kale Chane','Zarda Rice']}]},
    { day:'Tuesday',   tag:'Mid-Week Treat',   meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Aloo Paratha','Paratha','Egg','Phane','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Chicken White Handi','Dal Mong','Aloo Gajar']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Pulao','Chicken Sabzi']}]},
    { day:'Wednesday', tag:'Hump Day Special', meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Egg','Aloo Bhujia','Milk','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Dal Mong','White Rice','Mix Vegetables','Karhi Pakora']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Achari Gosht','Dal Chana','White Rice']}]},
    { day:'Thursday',  tag:'Almost Friday',    meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Aloo Paratha','Paratha','Egg','Phane','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Beef Nihari','Dal Chana','Vegetables']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Qorma','Dal Chana','Vegetables']}]},
    { day:'Friday',    tag:'Weekend Begins',   meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Aloo Paratha','Paratha','Egg','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Chicken Biryani','Aloo Chips','Dal Mong']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Beef Qorma','Dal Mash','Aloo Qeema']}]},
    { day:'Saturday',  tag:'Weekend Special',  meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Aloo Paratha','Paratha','Egg','Phane','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Mutton Kabab','Sabzi Pulao','Vegetables']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Pulao','Mutton Qorma','Dal']}]},
    { day:'Sunday',    tag:'Rest & Feast',     meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Egg','Aloo Bhujia','Milk','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Mutton Kabab','Sabzi Pulao']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Mutton Qorma','Dal','Vegetables']}]},
  ],
  'Staff Hostel-II Canteen': [
    { day:'Monday',    tag:'Start of Week',    meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Omelette','Chai']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Daal Chawal','Salad']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Karahi','Roti','Raita']}]},
    { day:'Tuesday',   tag:'Mid-Week Treat',   meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Halwa Puri','Aloo','Chai']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Chicken Pulao','Kachumber']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Beef Keema','Roti','Dal']}]},
    { day:'Wednesday', tag:'Hump Day Special', meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Egg','Milk','Tea']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Biryani','Raita','Salad']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Aloo Gosht','Roti','Dal Mash']}]},
    { day:'Thursday',  tag:'Almost Friday',    meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Aloo Paratha','Lassi']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Daal Makhni','Chawal','Roti']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Mutton Paya','Naan','Salad']}]},
    { day:'Friday',    tag:'Juma Special',     meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Paratha','Egg','Chai']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Pulao','Chicken Qorma','Raita']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Beef Handi','Roti','Salad']}]},
    { day:'Saturday',  tag:'Weekend Special',  meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Puri','Halwa','Chai']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Chicken Biryani','Salad']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Daal Gosht','Roti','Chawal']}]},
    { day:'Sunday',    tag:'Rest & Feast',     meals:[{label:'Breakfast',time:'7:00–9:00 AM',icon:'🍳',items:['Nihari','Naan','Chai']},{label:'Lunch',time:'12:30–2:30 PM',icon:'🍛',items:['Mix Pulao','Raita']},{label:'Dinner',time:'7:00–9:00 PM',icon:'🍲',items:['Chicken Handi','Roti','Dal']}]},
  ],
  'Cafeteria Canteen': [
    { day:'Monday',    tag:'Start of Week',    meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Sandwich','Juice','Tea/Coffee']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Pasta','Salad','Bread']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Samosa','Pakora','Chai']}]},
    { day:'Tuesday',   tag:'Mid-Week Treat',   meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Club Sandwich','Milk','Tea']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Fried Rice','Spring Rolls','Soup']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Cake Slice','Biscuits','Coffee']}]},
    { day:'Wednesday', tag:'Hump Day Special', meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Egg Toast','Juice','Tea']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Burger','Fries','Cold Drink']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Patties','Tea','Fruit']}]},
    { day:'Thursday',  tag:'Almost Friday',    meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Paratha Roll','Lassi']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Chicken Sandwich','Salad','Juice']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Donut','Coffee','Fruit']}]},
    { day:'Friday',    tag:'TGIF Special',     meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['French Toast','Juice','Tea']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Pizza Slice','Salad','Cold Drink']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Cake','Tea','Biscuits']}]},
    { day:'Saturday',  tag:'Weekend Vibes',    meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Waffle','Juice','Coffee']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['Grilled Chicken','Fries','Salad']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Brownie','Tea']}]},
    { day:'Sunday',    tag:'Rest & Relax',     meals:[{label:'Breakfast',time:'8:00–10:00 AM',icon:'☕',items:['Pancakes','Juice','Tea']},{label:'Lunch',time:'1:00–3:00 PM',icon:'🥗',items:['BBQ Platter','Garlic Bread','Soup']},{label:'Snacks',time:'4:00–5:00 PM',icon:'🍪',items:['Muffin','Coffee']}]},
  ],
};

const DEFAULT_CONTACTS_DATA = {
  'Plant Canteen':           [['Ahmad Naveed','03461113920'],['Ahmad Maqsood','03044467651'],['Iqbal Naeem','Committee']],
  'Staff Hostel-II Canteen': [['Ahmad Naveed','03461113920'],['Ahmad Maqsood','03044467651'],['Iqbal Naeem','Committee']],
  'Cafeteria Canteen':       [['Ahmad Naveed','03461113920'],['Ahmad Maqsood','03044467651'],['Iqbal Naeem','Committee']],
};

// ── Auth helpers ──────────────────────────────────────────
async function isPinValid(pin) {
  const p = String(pin || '').trim();
  if (!p) return false;
  if (p === SUPERADMIN_PIN) return true;
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim()) return true;
  } catch (e) {}
  try {
    const sub = await SubUser.findOne({ pin: p });
    if (sub) return true;
  } catch (e) {}
  return false;
}

async function verifyLogin(pin, username) {
  const p = String(pin     || '').trim();
  const u = String(username || '').trim().toLowerCase();
  if (!p || !u) return { valid: false, isSuperAdmin: false };
  if (u === SUPERADMIN_USER && p === SUPERADMIN_PIN) return { valid: true, isSuperAdmin: true };
  try {
    const cfg = await EmailConfig.findOne();
    if (cfg && cfg.adminPinOverride && p === String(cfg.adminPinOverride).trim())
      return { valid: true, isSuperAdmin: u === SUPERADMIN_USER };
  } catch (e) {}
  try {
    const sub = await SubUser.findOne({ username: u, pin: p });
    if (sub) return { valid: true, isSuperAdmin: false };
  } catch (e) {}
  return { valid: false, isSuperAdmin: false };
}

function getHeaderPin(req) {
  return req.headers['adminpin'] || req.headers['adminPin'] ||
         req.headers['admin-pin'] || req.headers['Admin-Pin'] || '';
}

// ════════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server running ✅', timestamp: new Date().toISOString() });
});

// ════════════════════════════════════════════════════════
// MENU — public GET, admin-only PUT
// ════════════════════════════════════════════════════════

// GET /api/menu  →  returns { menuData, contactData } for all canteens
app.get('/api/menu', async (req, res) => {
  try {
    const records = await Menu.find({});

    // Build response objects; fall back to defaults for any missing canteen
    const menuData    = {};
    const contactData = {};

    for (const canteen of CANTEEN_NAMES) {
      const rec = records.find(r => r.canteen === canteen);
      menuData[canteen]    = rec ? rec.days     : DEFAULT_MENU_DATA[canteen];
      contactData[canteen] = rec ? rec.contacts : DEFAULT_CONTACTS_DATA[canteen];
    }

    res.json({ menuData, contactData });
  } catch (e) {
    console.error('GET /menu error:', e);
    res.status(500).json({ error: 'Error fetching menu: ' + e.message });
  }
});

// PUT /api/menu  →  admin saves menu for one canteen
// Body: { canteen, days?, contacts? }
app.put('/api/menu', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized — invalid PIN' });

    const { canteen, days, contacts } = req.body;
    if (!canteen || !CANTEEN_NAMES.includes(canteen))
      return res.status(400).json({ error: 'Invalid canteen name' });

    const update = { updatedAt: new Date() };
    if (days     !== undefined) update.days     = days;
    if (contacts !== undefined) update.contacts = contacts;

    await Menu.findOneAndUpdate(
      { canteen },
      { $set: update },
      { upsert: true, new: true }
    );

    res.json({ success: true });
  } catch (e) {
    console.error('PUT /menu error:', e);
    res.status(500).json({ error: 'Error saving menu: ' + e.message });
  }
});

// PUT /api/menu/reset  →  admin resets all canteens to defaults
app.put('/api/menu/reset', async (req, res) => {
  try {
    const pin = getHeaderPin(req);
    if (!await isPinValid(pin))
      return res.status(401).json({ error: 'Unauthorized — invalid PIN' });

    await Menu.deleteMany({});
    res.json({ success: true, message: 'Menu reset to defaults' });
  } catch (e) {
    res.status(500).json({ error: 'Error resetting menu: ' + e.message });
  }
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
    res.json(await Complaint.find(query)
      .select('-imageUrl -videoUrl')
      .sort({ submittedAt: -1 }));
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
    const result = await verifyLogin(pin, username);
    if (result.valid) {
      res.json({ success: true, isSuperAdmin: result.isSuperAdmin });
    } else {
      res.status(401).json({ error: 'Invalid username or PIN' });
    }
  } catch (e) {
    res.status(500).json({ error: 'Login error: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
// ADMIN STATS
// ════════════════════════════════════════════════════════
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
      totalComplaints:      total,
      newComplaints:        newC,
      inProgressComplaints: inProg,
      resolvedComplaints:   resolved,
      byCanteen
    });
  } catch (e) {
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
    res.status(500).json({ error: 'Failed to send code. Error: ' + e.message });
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
