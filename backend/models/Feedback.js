const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  rating: {
    type: Number,
    required: [true, 'Rating is required'],
    min: [1, 'Rating must be at least 1'],
    max: [5, 'Rating cannot exceed 5'],
  },
  feedback: {
    type: String,
    required: [true, 'Feedback text is required'],
    trim: true,
    minlength: [10, 'Feedback must be at least 10 characters long'],
    maxlength: [500, 'Feedback cannot exceed 500 characters'],
  },
  category: {
    type: String,
    required: true,
    enum: ['general', 'feature', 'bug', 'ui', 'performance', 'other'],
    default: 'general',
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please enter a valid email',
    ],
  },
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'resolved', 'archived'],
    default: 'pending',
  },
  adminNotes: {
    type: String,
    trim: true,
    maxlength: [1000, 'Admin notes cannot exceed 1000 characters'],
  },
  isPublic: {
    type: Boolean,
    default: false, // Whether this feedback can be displayed publicly
  },
  helpful: {
    type: Number,
    default: 0, // Count of how many users found this feedback helpful
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true,
  }],
  metadata: {
    userAgent: String,
    ipAddress: String,
    deviceInfo: String,
    appVersion: String,
  },
}, {
  timestamps: true,
});

// Indexes for better query performance
feedbackSchema.index({ user: 1, createdAt: -1 });
feedbackSchema.index({ rating: 1 });
feedbackSchema.index({ category: 1 });
feedbackSchema.index({ status: 1 });
feedbackSchema.index({ createdAt: -1 });

// Virtual for feedback age
feedbackSchema.virtual('age').get(function() {
  return Date.now() - this.createdAt.getTime();
});

// Static method to get average rating
feedbackSchema.statics.getAverageRating = async function() {
  const result = await this.aggregate([
    {
      $group: {
        _id: null,
        averageRating: { $avg: '$rating' },
        totalFeedback: { $sum: 1 },
        ratingDistribution: {
          $push: '$rating'
        }
      }
    }
  ]);

  if (result.length === 0) {
    return {
      averageRating: 0,
      totalFeedback: 0,
      ratingDistribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
    };
  }

  const data = result[0];
  const distribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  
  data.ratingDistribution.forEach(rating => {
    distribution[rating] = (distribution[rating] || 0) + 1;
  });

  return {
    averageRating: Math.round(data.averageRating * 10) / 10, // Round to 1 decimal
    totalFeedback: data.totalFeedback,
    ratingDistribution: distribution
  };
};

// Static method to get feedback by category
feedbackSchema.statics.getFeedbackByCategory = async function() {
  return await this.aggregate([
    {
      $group: {
        _id: '$category',
        count: { $sum: 1 },
        averageRating: { $avg: '$rating' },
        latestFeedback: { $max: '$createdAt' }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);
};

// Instance method to mark as helpful
feedbackSchema.methods.markAsHelpful = function() {
  this.helpful += 1;
  return this.save();
};

// Pre-save middleware to sanitize feedback text
feedbackSchema.pre('save', function(next) {
  if (this.feedback) {
    // Basic sanitization - remove excessive whitespace
    this.feedback = this.feedback.replace(/\s+/g, ' ').trim();
  }
  next();
});

// Export the model
module.exports = mongoose.model('Feedback', feedbackSchema);
