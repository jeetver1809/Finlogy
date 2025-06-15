import React, { useState } from 'react';
import { GiftIcon, HeartIcon, SparklesIcon } from '@heroicons/react/24/outline';
import { HeartIcon as HeartIconSolid } from '@heroicons/react/24/solid';

const BuyMeCoffeeCard = () => {
  const [isHovered, setIsHovered] = useState(false);
  const [showThankYou, setShowThankYou] = useState(false);

  const handleCoffeeClick = () => {
    // Replace with your actual Buy Me a Coffee URL
    const buyMeCoffeeUrl = 'https://www.buymeacoffee.com/jeetverma';
    window.open(buyMeCoffeeUrl, '_blank', 'noopener,noreferrer');
    
    // Show thank you message
    setShowThankYou(true);
    setTimeout(() => setShowThankYou(false), 3000);
  };

  return (
    <div className="max-w-md mx-auto">
      <div 
        className={`
          relative bg-gradient-to-br from-amber-50 to-orange-100 dark:from-amber-900/20 dark:to-orange-900/20 
          rounded-2xl p-8 border-2 border-amber-200 dark:border-amber-700/50 shadow-lg
          transition-all duration-300 ease-in-out transform
          ${isHovered ? 'scale-105 shadow-2xl' : 'hover:scale-102'}
          interactive-card
        `}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {/* Coffee Steam Animation */}
        <div className="absolute top-4 right-4">
          <div className="relative">
            <div className="w-1 h-8 bg-gradient-to-t from-transparent via-gray-300 to-transparent opacity-60 animate-pulse"></div>
            <div className="absolute left-2 w-1 h-6 bg-gradient-to-t from-transparent via-gray-300 to-transparent opacity-40 animate-pulse" style={{ animationDelay: '0.5s' }}></div>
            <div className="absolute left-4 w-1 h-7 bg-gradient-to-t from-transparent via-gray-300 to-transparent opacity-50 animate-pulse" style={{ animationDelay: '1s' }}></div>
          </div>
        </div>

        {/* Main Content */}
        <div className="text-center">
          {/* Coffee Icon */}
          <div className="mb-6">
            <div className={`
              inline-flex items-center justify-center w-20 h-20 rounded-full 
              bg-gradient-to-br from-amber-400 to-orange-500 shadow-lg
              transition-all duration-300 ease-in-out
              ${isHovered ? 'rotate-12 scale-110' : ''}
            `}>
              <GiftIcon className="h-10 w-10 text-white" />
            </div>
          </div>

          {/* Title */}
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">
            Buy Me a Coffee
          </h3>

          {/* Description */}
          <p className="text-gray-600 dark:text-gray-400 mb-6 leading-relaxed">
            Fuel my coding sessions and help keep Finlogy running! 
            Your support enables me to add new features and maintain the app.
          </p>

          {/* Support Options */}
          <div className="grid grid-cols-3 gap-3 mb-6">
            <div className="text-center p-3 bg-white dark:bg-gray-800 rounded-lg border border-amber-200 dark:border-amber-700/50">
              <div className="text-lg font-bold text-amber-600 dark:text-amber-400">☕</div>
              <div className="text-xs text-gray-600 dark:text-gray-400">₹10</div>
            </div>
            <div className="text-center p-3 bg-white dark:bg-gray-800 rounded-lg border border-amber-200 dark:border-amber-700/50">
              <div className="text-lg font-bold text-amber-600 dark:text-amber-400">🥪</div>
              <div className="text-xs text-gray-600 dark:text-gray-400">₹100</div>
            </div>
            <div className="text-center p-3 bg-white dark:bg-gray-800 rounded-lg border border-amber-200 dark:border-amber-700/50">
              <div className="text-lg font-bold text-amber-600 dark:text-amber-400">🍕</div>
              <div className="text-xs text-gray-600 dark:text-gray-400">₹200</div>
            </div>
          </div>

          {/* CTA Button */}
          <button
            onClick={handleCoffeeClick}
            className={`
              w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600
              text-white font-semibold py-4 px-6 rounded-xl shadow-lg
              transition-all duration-300 ease-in-out transform
              focus:outline-none focus:ring-4 focus:ring-amber-300 dark:focus:ring-amber-700
              ${isHovered ? 'shadow-2xl' : ''}
              flex items-center justify-center space-x-2
            `}
          >
            <GiftIcon className="h-5 w-5" />
            <span>Support My Work</span>
            <HeartIconSolid className="h-5 w-5 text-red-300" />
          </button>

          {/* Thank You Message */}
          {showThankYou && (
            <div className="mt-4 p-3 bg-green-100 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded-lg">
              <div className="flex items-center justify-center space-x-2 text-green-700 dark:text-green-300">
                <SparklesIcon className="h-5 w-5" />
                <span className="font-medium">Thank you for your support! 🙏</span>
              </div>
            </div>
          )}

          {/* Additional Info */}
          <div className="mt-6 text-xs text-gray-500 dark:text-gray-400">
            <p>Secure payment via Buy Me a Coffee platform</p>
            <p className="mt-1">No account required • One-time support</p>
          </div>
        </div>

        {/* Decorative Elements */}
        <div className="absolute top-2 left-2 w-3 h-3 bg-amber-300 rounded-full opacity-60"></div>
        <div className="absolute bottom-2 right-8 w-2 h-2 bg-orange-400 rounded-full opacity-40"></div>
        <div className="absolute top-1/2 left-1 w-1 h-1 bg-amber-400 rounded-full opacity-50"></div>
      </div>

      {/* Additional Message */}
      <div className="mt-6 text-center">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Every contribution, no matter how small, makes a difference! 
          <br />
          <span className="font-medium">Thank you for believing in this project.</span>
        </p>
      </div>
    </div>
  );
};

export default BuyMeCoffeeCard;
