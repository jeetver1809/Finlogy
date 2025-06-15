const mongoose = require('mongoose');

const budgetSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  name: {
    type: String,
    required: [true, 'Budget name is required'],
    trim: true,
    maxlength: [100, 'Name cannot be more than 100 characters'],
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
      'total', // For overall budget
    ],
  },
  amount: {
    type: Number,
    required: [true, 'Budget amount is required'],
    min: [0.01, 'Amount must be greater than 0'],
  },
  period: {
    type: String,
    required: [true, 'Budget period is required'],
    enum: ['weekly', 'monthly', 'yearly'],
    default: 'monthly',
  },
  startDate: {
    type: Date,
    required: [true, 'Start date is required'],
    default: Date.now,
  },
  endDate: {
    type: Date,
    // Note: endDate is automatically calculated in pre-save middleware based on startDate and period
  },
  spent: {
    type: Number,
    default: 0,
    min: [0, 'Spent amount cannot be negative'],
  },
  alertThreshold: {
    type: Number,
    default: 80, // Alert when 80% of budget is spent
    min: [1, 'Alert threshold must be at least 1%'],
    max: [100, 'Alert threshold cannot exceed 100%'],
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot be more than 500 characters'],
  },
}, {
  timestamps: true,
});

// Index for better query performance
budgetSchema.index({ user: 1, category: 1 });
budgetSchema.index({ user: 1, isActive: 1 });
budgetSchema.index({ user: 1, endDate: 1 });

// Virtual for remaining budget
budgetSchema.virtual('remaining').get(function() {
  return Math.max(0, this.amount - this.spent);
});

// Virtual for percentage spent
budgetSchema.virtual('percentageSpent').get(function() {
  return Math.min(100, (this.spent / this.amount) * 100);
});

// Virtual for budget status
budgetSchema.virtual('status').get(function() {
  const percentage = this.percentageSpent;
  if (percentage >= 100) return 'exceeded';
  if (percentage >= this.alertThreshold) return 'warning';
  return 'on_track';
});

// Virtual for formatted amounts
budgetSchema.virtual('formattedAmount').get(function() {
  return this.amount.toFixed(2);
});

budgetSchema.virtual('formattedSpent').get(function() {
  return this.spent.toFixed(2);
});

budgetSchema.virtual('formattedRemaining').get(function() {
  return this.remaining.toFixed(2);
});

// Method to update spent amount
budgetSchema.methods.updateSpent = async function() {
  const Expense = mongoose.model('Expense');
  
  let matchStage = {
    user: this.user,
    date: {
      $gte: this.startDate,
      $lte: this.endDate,
    },
  };

  // If not total budget, filter by category
  if (this.category !== 'total') {
    matchStage.category = this.category;
  }

  const result = await Expense.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        total: { $sum: '$amount' },
      },
    },
  ]);

  this.spent = result.length > 0 ? result[0].total : 0;
  return this.save();
};

// Static method to get active budgets for a user
budgetSchema.statics.getActiveBudgets = function(userId) {
  return this.find({
    user: userId,
    isActive: true,
    endDate: { $gte: new Date() },
  }).sort({ createdAt: -1 });
};

// Static method to get budgets by category
budgetSchema.statics.getByCategory = function(userId, category) {
  return this.find({
    user: userId,
    category: category,
    isActive: true,
  }).sort({ createdAt: -1 });
};

// Pre-save middleware to set end date based on period
budgetSchema.pre('save', function(next) {
  if (this.isNew || this.isModified('startDate') || this.isModified('period')) {
    const start = new Date(this.startDate);
    let end = new Date(start);

    switch (this.period) {
      case 'weekly':
        end.setDate(start.getDate() + 7);
        break;
      case 'monthly':
        end.setMonth(start.getMonth() + 1);
        break;
      case 'yearly':
        end.setFullYear(start.getFullYear() + 1);
        break;
    }

    this.endDate = end;
  }
  next();
});

module.exports = mongoose.model('Budget', budgetSchema);
