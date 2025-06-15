import React, { useState } from 'react';
import { PaperAirplaneIcon, CheckCircleIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import StarRating from './StarRating';
import toast from 'react-hot-toast';
import { feedbackService } from '../../services/feedbackService';

const FeedbackForm = () => {
  const [formData, setFormData] = useState({
    rating: 0,
    feedback: '',
    category: 'general',
    email: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [errors, setErrors] = useState({});

  const categories = [
    { value: 'general', label: 'General Feedback' },
    { value: 'feature', label: 'Feature Request' },
    { value: 'bug', label: 'Bug Report' },
    { value: 'ui', label: 'User Interface' },
    { value: 'performance', label: 'Performance' },
    { value: 'other', label: 'Other' }
  ];

  const validateForm = () => {
    const newErrors = {};

    if (formData.rating === 0) {
      newErrors.rating = 'Please provide a rating';
    }

    if (!formData.feedback.trim()) {
      newErrors.feedback = 'Please share your feedback';
    } else if (formData.feedback.trim().length < 10) {
      newErrors.feedback = 'Feedback must be at least 10 characters long';
    }

    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      toast.error('Please fix the errors in the form');
      return;
    }

    setIsSubmitting(true);

    try {
      // Submit feedback using the feedback service
      await feedbackService.submitFeedback(formData);

      setIsSubmitted(true);
      toast.success('Thank you for your feedback!');
      
      // Reset form after successful submission
      setTimeout(() => {
        setFormData({
          rating: 0,
          feedback: '',
          category: 'general',
          email: ''
        });
        setIsSubmitted(false);
        setErrors({});
      }, 3000);

    } catch (error) {
      console.error('Error submitting feedback:', error);
      toast.error('Failed to submit feedback. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRatingChange = (rating) => {
    setFormData(prev => ({ ...prev, rating }));
    if (errors.rating) {
      setErrors(prev => ({ ...prev, rating: '' }));
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  if (isSubmitted) {
    return (
      <div className="max-w-2xl mx-auto">
        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700/50 rounded-lg p-8 text-center">
          <CheckCircleIcon className="h-16 w-16 text-green-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-green-800 dark:text-green-200 mb-2">
            Thank You!
          </h3>
          <p className="text-green-700 dark:text-green-300 mb-4">
            Your feedback has been submitted successfully. I really appreciate you taking the time to help improve Finlogy!
          </p>
          <div className="text-sm text-green-600 dark:text-green-400">
            You can submit another feedback in a few seconds...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Rating Section */}
          <div className="text-center">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-4">
              How would you rate your experience with Finlogy?
            </label>
            <StarRating
              rating={formData.rating}
              onRatingChange={handleRatingChange}
              size="lg"
              className="mb-2"
            />
            {errors.rating && (
              <p className="text-red-500 dark:text-red-400 text-sm mt-2 flex items-center justify-center">
                <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                {errors.rating}
              </p>
            )}
          </div>

          {/* Category Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Feedback Category
            </label>
            <select
              name="category"
              value={formData.category}
              onChange={handleInputChange}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm 
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                         focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {categories.map(category => (
                <option key={category.value} value={category.value}>
                  {category.label}
                </option>
              ))}
            </select>
          </div>

          {/* Feedback Text */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Your Feedback *
            </label>
            <textarea
              name="feedback"
              value={formData.feedback}
              onChange={handleInputChange}
              rows={5}
              placeholder="Share your thoughts, suggestions, or report any issues you've encountered..."
              className={`w-full px-3 py-2 border rounded-md shadow-sm resize-none
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                         placeholder-gray-500 dark:placeholder-gray-400
                         focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
                         ${errors.feedback ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'}`}
            />
            {errors.feedback && (
              <p className="text-red-500 dark:text-red-400 text-sm mt-1 flex items-center">
                <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                {errors.feedback}
              </p>
            )}
            <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {formData.feedback.length}/500 characters
            </div>
          </div>

          {/* Optional Email */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Email (Optional)
            </label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="your.email@example.com"
              className={`w-full px-3 py-2 border rounded-md shadow-sm
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                         placeholder-gray-500 dark:placeholder-gray-400
                         focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
                         ${errors.email ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'}`}
            />
            {errors.email && (
              <p className="text-red-500 dark:text-red-400 text-sm mt-1 flex items-center">
                <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                {errors.email}
              </p>
            )}
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Leave your email if you'd like a response to your feedback
            </p>
          </div>

          {/* Submit Button */}
          <div className="pt-4">
            <button
              type="submit"
              disabled={isSubmitting}
              className={`w-full flex items-center justify-center px-6 py-3 border border-transparent 
                         text-base font-medium rounded-md text-white shadow-sm
                         transition-all duration-200 ease-in-out
                         ${isSubmitting 
                           ? 'bg-gray-400 cursor-not-allowed' 
                           : 'bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
                         }`}
            >
              {isSubmitting ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                  Submitting...
                </>
              ) : (
                <>
                  <PaperAirplaneIcon className="h-5 w-5 mr-2" />
                  Submit Feedback
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default FeedbackForm;
