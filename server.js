// server.js - Backend Express Server
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB Connected');
}).catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
  process.exit(1);
});

// Models Import
const Complaint = require('./models/Complaint');
const AdminUser = require('./models/AdminUser');
const EmailConfig = require('./models/EmailConfig');

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server running ✅' });
});

// ==================== COMPLAINT ROUTES ====================

// Submit new complaint
app.post('/api/complaints', async (req, res) => {
  try {
    const { fullName, personalNumber, designation, department, mobileNumber, complaintDetails, canteen, imageUrl, videoUrl } = req.body;

    // Validation
    if (!fullName || !personalNumber || !designation || !department || !mobileNumber || !complaintDetails || !canteen) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const complaint = new Complaint({
      fullName,
      personalNumber,
      designation,
      department,
      mobileNumber,
      complaintDetails,
      canteen,
      imageUrl: imageUrl || null,
      videoUrl: videoUrl || null,
      status: 'New',
      submittedAt: new Date(),
      remarks: []
    });

    await complaint.save();

    // Send email to admins
    sendComplaintNotification(complaint);

    res.status(201).json({
      success: true,
      message: 'Complaint submitted successfully',
      complaintId: complaint._id
    });

  } catch (error) {
    console.error('Error submitting complaint:', error);
    res.status(500).json({ error: 'Error submitting complaint' });
  }
});

// Get all complaints (with filters)
app.get('/api/complaints', async (req, res) => {
  try {
    const { canteen, status, searchTerm } = req.query;
    let query = {};

    if (canteen) query.canteen = canteen;
    if (status) query.status = status;
    if (searchTerm) {
      query.$or = [
        { fullName: new RegExp(searchTerm, 'i') },
        { personalNumber: new RegExp(searchTerm, 'i') },
        { complaintDetails: new RegExp(searchTerm, 'i') }
      ];
    }

    const complaints = await Complaint.find(query).sort({ submittedAt: -1 });
    res.json(complaints);

  } catch (error) {
    console.error('Error fetching complaints:', error);
    res.status(500).json({ error: 'Error fetching complaints' });
  }
});

// Get single complaint
app.get('/api/complaints/:id', async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) {
      return res.status(404).json({ error: 'Complaint not found' });
    }
    res.json(complaint);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching complaint' });
  }
});

// Update complaint (admin only)
app.put('/api/complaints/:id', async (req, res) => {
  try {
    const { adminPin } = req.headers;
    
    if (adminPin !== process.env.ADMIN_PIN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { status, remarks, fineAmount, investigation } = req.body;
    const complaint = await Complaint.findByIdAndUpdate(
      req.params.id,
      {
        status: status || undefined,
        fineAmount: fineAmount || undefined,
        investigation: investigation || undefined,
        updatedAt: new Date()
      },
      { new: true }
    );

    if (remarks) {
      complaint.remarks.push({
        text: remarks,
        addedAt: new Date()
      });
      await complaint.save();
    }

    // Send email to complainant
    sendUpdateNotification(complaint);

    res.json({ success: true, complaint });

  } catch (error) {
    console.error('Error updating complaint:', error);
    res.status(500).json({ error: 'Error updating complaint' });
  }
});

// Delete complaint (admin only)
app.delete('/api/complaints/:id', async (req, res) => {
  try {
    const { adminPin } = req.headers;
    
    if (adminPin !== process.env.ADMIN_PIN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    await Complaint.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Complaint deleted' });

  } catch (error) {
    res.status(500).json({ error: 'Error deleting complaint' });
  }
});

// ==================== ADMIN ROUTES ====================

// Verify admin PIN
app.post('/api/admin/verify-pin', (req, res) => {
  const { pin } = req.body;
  
  if (pin === process.env.ADMIN_PIN) {
    res.json({ success: true, token: 'admin_authenticated' });
  } else {
    res.status(401).json({ error: 'Invalid PIN' });
  }
});

// Get admin dashboard stats
app.get('/api/admin/stats', async (req, res) => {
  try {
    const { adminPin } = req.headers;
    
    if (adminPin !== process.env.ADMIN_PIN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const totalComplaints = await Complaint.countDocuments();
    const newComplaints = await Complaint.countDocuments({ status: 'New' });
    const inProgressComplaints = await Complaint.countDocuments({ status: 'In Progress' });
    const resolvedComplaints = await Complaint.countDocuments({ status: 'Resolved' });

    const byCanteen = await Complaint.aggregate([
      {
        $group: {
          _id: '$canteen',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      totalComplaints,
      newComplaints,
      inProgressComplaints,
      resolvedComplaints,
      byCanteen
    });

  } catch (error) {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

// ==================== EMAIL CONFIG ROUTES ====================

// Get email config
app.get('/api/admin/email-config', async (req, res) => {
  try {
    const { adminPin } = req.headers;
    
    if (adminPin !== process.env.ADMIN_PIN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    let config = await EmailConfig.findOne();
    if (!config) {
      config = new EmailConfig({
        recipients: [],
        enableNotifications: true
      });
      await config.save();
    }
    res.json(config);

  } catch (error) {
    res.status(500).json({ error: 'Error fetching email config' });
  }
});

// Update email config
app.put('/api/admin/email-config', async (req, res) => {
  try {
    const { adminPin } = req.headers;
    
    if (adminPin !== process.env.ADMIN_PIN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { recipients, enableNotifications } = req.body;

    let config = await EmailConfig.findOne();
    if (!config) {
      config = new EmailConfig();
    }

    config.recipients = recipients || config.recipients;
    config.enableNotifications = enableNotifications !== undefined ? enableNotifications : config.enableNotifications;

    await config.save();
    res.json({ success: true, config });

  } catch (error) {
    res.status(500).json({ error: 'Error updating email config' });
  }
});

// ==================== EMAIL FUNCTIONS ====================

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

async function sendComplaintNotification(complaint) {
  try {
    const config = await EmailConfig.findOne();
    if (!config || !config.enableNotifications) return;

    const recipients = config.recipients.join(', ');
    if (!recipients) return;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: recipients,
      subject: `🔔 New Complaint Submitted - ${complaint.canteen}`,
      html: `
        <h2>New Complaint Received</h2>
        <p><strong>Canteen:</strong> ${complaint.canteen}</p>
        <p><strong>Name:</strong> ${complaint.fullName}</p>
        <p><strong>P. No:</strong> ${complaint.personalNumber}</p>
        <p><strong>Department:</strong> ${complaint.department}</p>
        <p><strong>Mobile:</strong> ${complaint.mobileNumber}</p>
        <p><strong>Complaint:</strong></p>
        <p>${complaint.complaintDetails}</p>
        <p><strong>Status:</strong> ${complaint.status}</p>
        <p>Complaint ID: ${complaint._id}</p>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✉️ Notification email sent for complaint ${complaint._id}`);
  } catch (error) {
    console.error('Error sending notification:', error);
  }
}

async function sendUpdateNotification(complaint) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: complaint.mobileNumber.includes('@') ? complaint.mobileNumber : `${complaint.mobileNumber}@companydomain.com`,
      subject: `📋 Complaint Status Update - ${complaint.canteen}`,
      html: `
        <h2>Your Complaint Status Update</h2>
        <p><strong>Canteen:</strong> ${complaint.canteen}</p>
        <p><strong>Status:</strong> ${complaint.status}</p>
        <p><strong>Fine Amount:</strong> ${complaint.fineAmount || 'N/A'}</p>
        <p><strong>Investigation:</strong> ${complaint.investigation || 'In Progress'}</p>
        <p><strong>Remarks:</strong></p>
        <ul>
          ${complaint.remarks.map(r => `<li>${r.text} (${new Date(r.addedAt).toLocaleString()})</li>`).join('')}
        </ul>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✉️ Update email sent for complaint ${complaint._id}`);
  } catch (error) {
    console.error('Error sending update email:', error);
  }
}

// ==================== SERVER START ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║  FFC MM - Canteens Backend Running   ║
║  Port: ${PORT}                            ║
║  Status: ✅ Online                   ║
╚══════════════════════════════════════╝
  `);
});

module.exports = app;
