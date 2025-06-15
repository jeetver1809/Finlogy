const mongoose = require('mongoose');

const incomeSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: [true, 'Income title is required'],
    trim: true,
    maxlength: [100, 'Title cannot be more than 100 characters'],
  },
  amount: {
    type: Number,
    required: [true, 'Amount is required'],
    min: [0.01, 'Amount must be greater than 0'],
  },
  source: {
    type: String,
    required: [true, 'Income source is required'],
    enum: [
      'salary',
      'freelance',
      'business',
      'investment',
      'rental',
      'bonus',
      'gift',
      'refund',
      'other',
    ],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot be more than 500 characters'],
  },
  date: {
    type: Date,
    required: [true, 'Date is required'],
    default: Date.now,
  },
  isRecurring: {
    type: Boolean,
    default: false,
  },
  recurringFrequency: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    required: function() {
      return this.isRecurring;
    },
  },
  recurringEndDate: {
    type: Date,
    required: function() {
      return this.isRecurring;
    },
  },
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag cannot be more than 30 characters'],
  }],
}, {
  timestamps: true,
});

// Index for better query performance
incomeSchema.index({ user: 1, date: -1 });
incomeSchema.index({ user: 1, source: 1 });
incomeSchema.index({ user: 1, createdAt: -1 });

// Virtual for formatted amount
incomeSchema.virtual('formattedAmount').get(function() {
  return this.amount.toFixed(2);
});

// Static method to get income by date range
incomeSchema.statics.getByDateRange = function(userId, startDate, endDate) {
  return this.find({
    user: userId,
    date: {
      $gte: startDate,
      $lte: endDate,
    },
  }).sort({ date: -1 });
};

// Static method to get income by source
incomeSchema.statics.getBySource = function(userId, source) {
  return this.find({
    user: userId,
    source: source,
  }).sort({ date: -1 });
};

// Static method to get total income for a user
incomeSchema.statics.getTotalIncome = function(userId, startDate, endDate) {
  const matchStage = { user: new mongoose.Types.ObjectId(userId) };
  
  if (startDate && endDate) {
    matchStage.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        total: { $sum: '$amount' },
        count: { $sum: 1 },
      },
    },
  ]);
};

module.exports = mongoose.model('Income', incomeSchema);
