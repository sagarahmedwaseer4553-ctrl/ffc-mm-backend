// models/Complaint.js
const mongoose = require('mongoose');

const complaintSchema = new mongoose.Schema({
  // User Info
  fullName: {
    type: String,
    required: true
  },
  personalNumber: {
    type: String,
    required: true
  },
  designation: {
    type: String,
    required: true
  },
  department: {
    type: String,
    required: true
  },
  mobileNumber: {
    type: String,
    required: true
  },

  // Complaint Details
  complaintDetails: {
    type: String,
    required: true
  },
  canteen: {
    type: String,
    enum: ['Plant Canteen', 'Staff Hostel-II Canteen'],
    required: true
  },
  imageUrl: String,
  videoUrl: String,

  // Status & Admin Actions
  status: {
    type: String,
    enum: ['New', 'In Progress', 'Under Investigation', 'Resolved', 'Closed'],
    default: 'New'
  },
  remarks: [
    {
      text: String,
      addedAt: {
        type: Date,
        default: Date.now
      }
    }
  ],
  fineAmount: {
    type: Number,
    default: 0
  },
  investigation: String,

  // Timestamps
  submittedAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  resolvedAt: Date
});

module.exports = mongoose.model('Complaint', complaintSchema);
