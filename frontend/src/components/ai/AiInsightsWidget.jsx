/**
 * 💡 AI INSIGHTS WIDGET
 * 
 * Dashboard widget that displays AI-generated financial insights
 * Features:
 * - Auto-generated insights based on user data
 * - Refresh functionality
 * - Loading states
 * - Error handling
 */

import React, { useState, useEffect } from 'react';
import { 
  SparklesIcon, 
  ArrowPathIcon,
  LightBulbIcon,
  ExclamationTriangleIcon,
  ChatBubbleLeftRightIcon
} from '@heroicons/react/24/outline';
import { aiService } from '../../services/aiService';
import LoadingSpinner from '../ui/LoadingSpinner';
import toast from 'react-hot-toast';
import { formatInsightsAsParagraphs } from '../../utils/aiFormatting.jsx';

const AiInsightsWidget = ({
  period = 'month',
  onOpenChat,
  onOpenChatWithContent, // New prop for pre-loading chat with insights
  className = ''
}) => {
  const [insights, setInsights] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  // Removed isExpanded state - using AI chat integration instead

  useEffect(() => {
    generateInsights();
  }, [period]);

  const generateInsights = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const aiInsights = await aiService.generateInsights(period);
      setInsights(aiInsights);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Failed to generate insights:', error);

      // Check if it's a network/service issue
      if (error.message.includes('Network connectivity') ||
          error.message.includes('Service temporarily unavailable') ||
          error.message.includes('timeout')) {
        setError('AI insights are temporarily unavailable due to network issues. Showing basic analytics instead.');
        // Don't show toast for network issues, just display fallback
      } else {
        setError(error.message);
        toast.error('Failed to generate AI insights');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefresh = () => {
    generateInsights();
  };



  // Function to open chat with pre-loaded insights
  const openChatWithInsights = () => {
    if (onOpenChatWithContent && insights) {
      // Pre-load the chat with full insights
      onOpenChatWithContent(insights);
    } else if (onOpenChat) {
      // Fallback to regular chat opening
      onOpenChat();
    }
  };

  const shouldShowChatButton = insights && insights.length > 150;

  return (
    <div className={`ai-insights-featured interactive-card bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 transition-all duration-200 hover:shadow-xl hover:scale-[1.01] ${className}`}>
      {/* Header */}
      <div className="ai-header p-5 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="ai-icon-container p-2 bg-gradient-to-br from-purple-100 to-blue-100 dark:from-purple-900/50 dark:to-blue-900/50 rounded-lg border border-purple-200 dark:border-purple-700/50 shadow-sm">
              <SparklesIcon className="h-5 w-5 text-purple-600 dark:text-purple-400 ai-sparkle animate-pulse" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center space-x-2">
                <span>AI Insights</span>
                <span className="ai-badge">✨</span>
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Powered by Gemini AI
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={handleRefresh}
              disabled={isLoading}
              className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-all duration-200 disabled:opacity-50 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg hover:scale-110"
              title="Refresh insights"
            >
              <ArrowPathIcon className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            
            {onOpenChat && (
              <button
                onClick={onOpenChat}
                className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-all duration-200 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg hover:scale-110"
                title="Open AI chat"
              >
                <ChatBubbleLeftRightIcon className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-5">
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="text-center">
              <LoadingSpinner size="md" />
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                Analyzing your financial data...
              </p>
            </div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-8">
            <div className="text-center">
              {error.includes('network') || error.includes('temporarily unavailable') ? (
                <>
                  <div className="h-12 w-12 bg-yellow-100 dark:bg-yellow-900/50 rounded-full flex items-center justify-center mx-auto mb-3">
                    <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
                  </div>
                  <p className="text-sm text-yellow-700 dark:text-yellow-300 mb-3">
                    {error}
                  </p>
                  <div className="flex space-x-2 justify-center">
                    <button
                      onClick={handleRefresh}
                      className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors text-sm"
                    >
                      Retry AI Insights
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-3" />
                  <p className="text-sm text-red-600 dark:text-red-400 mb-3">
                    {error}
                  </p>
                  <button
                    onClick={handleRefresh}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm"
                  >
                    Try Again
                  </button>
                </>
              )}
            </div>
          </div>
        ) : insights ? (
          <div className="space-y-3">
            {/* Smart Preview with Natural Paragraph Flow */}
            <div className="ai-content-container space-y-2">
              {formatInsightsAsParagraphs(insights, true)}
            </div>

            {/* View Full Analysis in Chat Button */}
            {shouldShowChatButton && (
              <div className="flex justify-center pt-2">
                <button
                  onClick={openChatWithInsights}
                  className="inline-flex items-center space-x-2 px-4 py-2 ai-gradient-button text-white rounded-lg transition-all duration-200 text-sm font-medium hover:shadow-lg hover:scale-[1.02] interactive-card border border-blue-500/20"
                >
                  <ChatBubbleLeftRightIcon className="h-4 w-4" />
                  <span>View Full Analysis in Chat</span>
                  <SparklesIcon className="h-4 w-4 animate-pulse" />
                </button>
              </div>
            )}

            {/* Footer */}
            <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
                <div className="flex items-center space-x-1">
                  <LightBulbIcon className="h-3 w-3" />
                  <span>AI-generated insights</span>
                </div>
                {lastUpdated && (
                  <span>
                    Updated {lastUpdated.toLocaleTimeString()}
                  </span>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center py-8">
            <div className="text-center">
              <SparklesIcon className="h-12 w-12 text-gray-400 mx-auto mb-3" />
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
                No insights available yet
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500">
                Add some transactions to get personalized insights
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      {insights && !isLoading && (
        <div className="px-5 pb-5">
          <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
            <div className="text-xs text-gray-600 dark:text-gray-400 mb-3 font-medium">
              Continue the conversation about your insights
            </div>
            <div className="flex">
              <button
                onClick={openChatWithInsights}
                className="w-full px-3 py-2 ai-gradient-button text-white rounded-md transition-all duration-200 text-sm font-medium hover:shadow-lg hover:scale-[1.02] interactive-card border border-blue-500/20"
              >
                <div className="flex items-center justify-center space-x-2">
                  <ChatBubbleLeftRightIcon className="h-4 w-4" />
                  <span>Chat About Insights</span>
                  <SparklesIcon className="h-3 w-3 animate-pulse" />
                </div>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AiInsightsWidget;
