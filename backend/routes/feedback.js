const express = require('express');
const router = express.Router();
const Feedback = require('../models/Feedback');
const { protect } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');

// Rate limiting for feedback submission
const feedbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each user to 3 feedback submissions per windowMs
  message: {
    success: false,
    message: 'Too many feedback submissions. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// @route   POST /api/feedback
// @desc    Submit feedback
// @access  Private
router.post('/', [protect, feedbackLimiter], async (req, res) => {
  try {
    const { rating, feedback, category, email } = req.body;

    // Validation
    if (!rating || !feedback) {
      return res.status(400).json({
        success: false,
        message: 'Rating and feedback are required',
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        message: 'Rating must be between 1 and 5',
      });
    }

    if (feedback.trim().length < 10) {
      return res.status(400).json({
        success: false,
        message: 'Feedback must be at least 10 characters long',
      });
    }

    // Check if user has already submitted feedback recently (within 24 hours)
    const recentFeedback = await Feedback.findOne({
      user: req.user.id,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    if (recentFeedback) {
      return res.status(429).json({
        success: false,
        message: 'You can only submit one feedback per day. Thank you for your previous feedback!',
      });
    }

    // Extract metadata from request
    const metadata = {
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip,
      deviceInfo: req.get('X-Device-Info') || 'Unknown',
      appVersion: req.get('X-App-Version') || '1.0.0',
    };

    // Create feedback
    const newFeedback = new Feedback({
      user: req.user.id,
      rating: parseInt(rating),
      feedback: feedback.trim(),
      category: category || 'general',
      email: email || req.user.email,
      metadata,
    });

    await newFeedback.save();

    // Populate user info for response
    await newFeedback.populate('user', 'name email');

    res.status(201).json({
      success: true,
      message: 'Thank you for your feedback!',
      data: {
        id: newFeedback._id,
        rating: newFeedback.rating,
        category: newFeedback.category,
        createdAt: newFeedback.createdAt,
      },
    });

  } catch (error) {
    console.error('❌ Feedback submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit feedback',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
    });
  }
});

// @route   GET /api/feedback/stats
// @desc    Get feedback statistics (public)
// @access  Public
router.get('/stats', async (req, res) => {
  try {
    const stats = await Feedback.getAverageRating();
    const categoryStats = await Feedback.getFeedbackByCategory();

    res.json({
      success: true,
      data: {
        overall: stats,
        byCategory: categoryStats,
        lastUpdated: new Date().toISOString(),
      },
    });

  } catch (error) {
    console.error('❌ Feedback stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch feedback statistics',
    });
  }
});

// @route   GET /api/feedback/my
// @desc    Get user's own feedback history
// @access  Private
router.get('/my', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const feedback = await Feedback.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-metadata -adminNotes');

    const total = await Feedback.countDocuments({ user: req.user.id });

    res.json({
      success: true,
      data: {
        feedback,
        pagination: {
          current: page,
          pages: Math.ceil(total / limit),
          total,
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1,
        },
      },
    });

  } catch (error) {
    console.error('❌ User feedback history error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch feedback history',
    });
  }
});

// @route   PUT /api/feedback/:id/helpful
// @desc    Mark feedback as helpful
// @access  Private
router.put('/:id/helpful', protect, async (req, res) => {
  try {
    const feedback = await Feedback.findById(req.params.id);

    if (!feedback) {
      return res.status(404).json({
        success: false,
        message: 'Feedback not found',
      });
    }

    // Users can't mark their own feedback as helpful
    if (feedback.user.toString() === req.user.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot mark your own feedback as helpful',
      });
    }

    await feedback.markAsHelpful();

    res.json({
      success: true,
      message: 'Feedback marked as helpful',
      data: {
        helpful: feedback.helpful,
      },
    });

  } catch (error) {
    console.error('❌ Mark feedback helpful error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark feedback as helpful',
    });
  }
});

// @route   GET /api/feedback/public
// @desc    Get public feedback (for testimonials, etc.)
// @access  Public
router.get('/public', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const minRating = parseInt(req.query.minRating) || 4;

    const feedback = await Feedback.find({
      isPublic: true,
      rating: { $gte: minRating },
    })
      .populate('user', 'name')
      .sort({ helpful: -1, createdAt: -1 })
      .limit(limit)
      .select('rating feedback category createdAt helpful user');

    res.json({
      success: true,
      data: feedback,
    });

  } catch (error) {
    console.error('❌ Public feedback error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch public feedback',
    });
  }
});

module.exports = router;
