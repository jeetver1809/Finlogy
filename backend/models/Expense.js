const mongoose = require('mongoose');

const expenseSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: [true, 'Expense title is required'],
    trim: true,
    maxlength: [100, 'Title cannot be more than 100 characters'],
  },
  amount: {
    type: Number,
    required: [true, 'Amount is required'],
    min: [0.01, 'Amount must be greater than 0'],
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: [
      'food',
      'transportation',
      'utilities',
      'entertainment',
      'healthcare',
      'shopping',
      'education',
      'travel',
      'insurance',
      'housing',
      'personal',
      'business',
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
  paymentMethod: {
    type: String,
    enum: ['cash', 'credit_card', 'debit_card', 'bank_transfer', 'digital_wallet', 'other'],
    default: 'cash',
  },
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag cannot be more than 30 characters'],
  }],
  receipt: {
    type: String, // URL to receipt image
    default: '',
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
}, {
  timestamps: true,
});

// Index for better query performance
expenseSchema.index({ user: 1, date: -1 });
expenseSchema.index({ user: 1, category: 1 });
expenseSchema.index({ user: 1, createdAt: -1 });

// Virtual for formatted amount
expenseSchema.virtual('formattedAmount').get(function() {
  return this.amount.toFixed(2);
});

// Static method to get expenses by date range
expenseSchema.statics.getByDateRange = function(userId, startDate, endDate) {
  return this.find({
    user: userId,
    date: {
      $gte: startDate,
      $lte: endDate,
    },
  }).sort({ date: -1 });
};

// Static method to get expenses by category
expenseSchema.statics.getByCategory = function(userId, category) {
  return this.find({
    user: userId,
    category: category,
  }).sort({ date: -1 });
};

// Static method to get total expenses for a user
expenseSchema.statics.getTotalExpenses = function(userId, startDate, endDate) {
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

module.exports = mongoose.model('Expense', expenseSchema);
