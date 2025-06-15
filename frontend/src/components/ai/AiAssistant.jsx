/**
 * 🤖 AI ASSISTANT COMPONENT
 * 
 * Interactive AI chat assistant for financial guidance
 * Features:
 * - Real-time chat with AI
 * - Financial context awareness
 * - Quick action buttons
 * - Message history
 */

import React, { useState, useRef, useEffect } from 'react';
import { 
  ChatBubbleLeftRightIcon, 
  PaperAirplaneIcon, 
  XMarkIcon,
  SparklesIcon,
  LightBulbIcon,
  ChartBarIcon,
  CurrencyRupeeIcon
} from '@heroicons/react/24/outline';
import { aiService } from '../../services/aiService';
import LoadingSpinner from '../ui/LoadingSpinner';
import toast from 'react-hot-toast';
import { convertTextToBulletPoints, formatBulletPointsForChat } from '../../utils/aiFormatting.jsx';

const AiAssistant = ({ isOpen, onClose, preloadedContent = null, className = '' }) => {
  // Persistent state management - maintains chat state across opens/closes
  const [messages, setMessages] = useState(() => {
    try {
      const savedMessages = localStorage.getItem('aiChatMessages');
      if (savedMessages) {
        const parsedMessages = JSON.parse(savedMessages);
        // Convert timestamp strings back to Date objects and validate
        return parsedMessages.map(msg => ({
          ...msg,
          timestamp: msg.timestamp ? new Date(msg.timestamp) : new Date()
        }));
      }
    } catch (error) {
      console.warn('Failed to load saved chat messages, resetting:', error);
      localStorage.removeItem('aiChatMessages');
    }

    return [
      {
        type: 'ai',
        content: '👋 Hi! I\'m your AI financial assistant. I can help you with budgeting, expense analysis, and financial planning. What would you like to know?',
        timestamp: new Date()
      }
    ];
  });
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [aiStatus, setAiStatus] = useState({ aiAvailable: true });
  const [chatPosition, setChatPosition] = useState(() => {
    const savedPosition = localStorage.getItem('aiChatPosition');
    return savedPosition ? JSON.parse(savedPosition) : { x: 0, y: 0 };
  });

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const chatModalRef = useRef(null);

  // Quick action suggestions
  const quickActions = [
    { text: 'Analyze my spending patterns', icon: ChartBarIcon },
    { text: 'How can I save more money?', icon: CurrencyRupeeIcon },
    { text: 'Review my budget performance', icon: LightBulbIcon },
    { text: 'What are my biggest expenses?', icon: SparklesIcon }
  ];

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Focus input when component opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Check AI service status on mount
  useEffect(() => {
    checkAiStatus();
  }, []);

  // Save messages to localStorage when they change
  useEffect(() => {
    localStorage.setItem('aiChatMessages', JSON.stringify(messages));
  }, [messages]);

  // Maintain scroll position when reopening chat
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => scrollToBottom(), 100);
    }
  }, [isOpen]);

  // Handle preloaded content when chat opens
  useEffect(() => {
    if (isOpen && preloadedContent) {
      // Convert content to bullet points for better readability
      const bulletPoints = convertTextToBulletPoints(preloadedContent);
      const formattedContent = formatBulletPointsForChat(bulletPoints);

      // Add the preloaded content as an AI message
      const preloadedMessage = {
        type: 'ai',
        content: `📊 **Complete AI Financial Analysis**\n\n${formattedContent}\n\n---\n\n💬 Feel free to ask me any questions about this analysis or your finances!`,
        timestamp: new Date(),
        isPreloaded: true
      };

      setMessages(prev => {
        // Check if this content is already loaded to avoid duplicates
        const hasPreloadedContent = prev.some(msg => msg.isPreloaded && msg.content.includes(preloadedContent.substring(0, 50)));
        if (!hasPreloadedContent) {
          return [...prev, preloadedMessage];
        }
        return prev;
      });
    }
  }, [isOpen, preloadedContent]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const checkAiStatus = async () => {
    try {
      const status = await aiService.getStatus();
      setAiStatus(status);
    } catch (error) {
      console.error('Failed to check AI status:', error);
      setAiStatus({ aiAvailable: false });
    }
  };

  const sendMessage = async (messageText = input) => {
    if (!messageText.trim() || isLoading) return;

    const userMessage = messageText.trim();
    setInput('');
    
    // Add user message
    const newUserMessage = {
      type: 'user',
      content: userMessage,
      timestamp: new Date()
    };
    
    setMessages(prev => [...prev, newUserMessage]);
    setIsLoading(true);

    try {
      // Get AI response
      const aiResponse = await aiService.chatWithAI(userMessage);
      
      // Add AI response
      const newAiMessage = {
        type: 'ai',
        content: aiResponse,
        timestamp: new Date()
      };
      
      setMessages(prev => [...prev, newAiMessage]);
    } catch (error) {
      console.error('AI chat error:', error);
      
      // Add error message
      const errorMessage = {
        type: 'ai',
        content: 'I apologize, but I\'m having trouble responding right now. Please try again in a moment. 🤖',
        timestamp: new Date(),
        isError: true
      };
      
      setMessages(prev => [...prev, errorMessage]);
      toast.error('Failed to get AI response');
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleQuickAction = (actionText) => {
    sendMessage(actionText);
  };

  const clearChat = () => {
    const newMessages = [
      {
        type: 'ai',
        content: '👋 Chat cleared! How can I help you with your finances today?',
        timestamp: new Date()
      }
    ];
    setMessages(newMessages);
    localStorage.setItem('aiChatMessages', JSON.stringify(newMessages));
  };

  // Reset chat data if corrupted
  const resetChatData = () => {
    localStorage.removeItem('aiChatMessages');
    const defaultMessages = [
      {
        type: 'ai',
        content: '👋 Hi! I\'m your AI financial assistant. I can help you with budgeting, expense analysis, and financial planning. What would you like to know?',
        timestamp: new Date()
      }
    ];
    setMessages(defaultMessages);
    localStorage.setItem('aiChatMessages', JSON.stringify(defaultMessages));
  };

  if (!isOpen) return null;

  return (
    <div className={`fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4 ${className}`}>
      <div
        ref={chatModalRef}
        className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-2xl h-[600px] flex flex-col transform transition-all duration-200 ease-out scale-100"
        style={{
          maxHeight: 'calc(100vh - 2rem)',
          minHeight: '500px'
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <ChatBubbleLeftRightIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                AI Financial Assistant
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {aiStatus.aiAvailable ? '🟢 Online' : '🔴 Offline'}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={clearChat}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
              title="Clear chat"
            >
              <SparklesIcon className="h-5 w-5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
              title="Close"
            >
              <XMarkIcon className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] p-3 rounded-lg ${
                  message.type === 'user'
                    ? 'bg-blue-600 text-white'
                    : message.isError
                    ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white'
                }`}
              >
                <div className="text-sm font-medium mb-1">
                  {message.type === 'user' ? '👤 You' : '🤖 AI Assistant'}
                </div>
                <div className="text-sm whitespace-pre-wrap">
                  {message.content}
                </div>
                <div className="text-xs opacity-70 mt-2">
                  {message.timestamp instanceof Date
                    ? message.timestamp.toLocaleTimeString()
                    : new Date(message.timestamp).toLocaleTimeString()
                  }
                </div>
              </div>
            </div>
          ))}
          
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-gray-100 dark:bg-gray-700 p-3 rounded-lg">
                <div className="text-sm font-medium mb-1">🤖 AI Assistant</div>
                <div className="flex items-center space-x-2">
                  <LoadingSpinner size="sm" />
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    Thinking...
                  </span>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Quick Actions */}
        {messages.length <= 1 && (
          <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-700">
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">
              Quick actions:
            </div>
            <div className="flex flex-wrap gap-2">
              {quickActions.map((action, index) => (
                <button
                  key={index}
                  onClick={() => handleQuickAction(action.text)}
                  className="flex items-center space-x-1 px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                >
                  <action.icon className="h-3 w-3" />
                  <span>{action.text}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex space-x-2">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={aiStatus.aiAvailable ? "Ask about your finances..." : "AI assistant is offline"}
              disabled={isLoading || !aiStatus.aiAvailable}
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors disabled:opacity-50"
            />
            <button
              onClick={() => sendMessage()}
              disabled={!input.trim() || isLoading || !aiStatus.aiAvailable}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center space-x-1"
            >
              {isLoading ? (
                <LoadingSpinner size="sm" />
              ) : (
                <PaperAirplaneIcon className="h-4 w-4" />
              )}
            </button>
          </div>
          
          {!aiStatus.aiAvailable && (
            <div className="mt-2 text-xs text-red-600 dark:text-red-400">
              ⚠️ AI assistant is currently unavailable. Please check your configuration.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AiAssistant;
