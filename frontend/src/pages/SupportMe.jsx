import React, { useState } from 'react';
import { HeartIcon, StarIcon, GiftIcon, UserIcon } from '@heroicons/react/24/outline';
import { HeartIcon as HeartIconSolid, StarIcon as StarIconSolid } from '@heroicons/react/24/solid';
import toast from 'react-hot-toast';

// Import components (we'll create these)
import AboutMe from '../components/support/AboutMe';
import BuyMeCoffeeCard from '../components/support/BuyMeCoffeeCard';
import FeedbackForm from '../components/support/FeedbackForm';
import SocialMediaCards from '../components/support/SocialMediaCards';

const SupportMe = () => {
  const [activeSection, setActiveSection] = useState('about');

  const sections = [
    { id: 'about', name: 'About Me', icon: UserIcon },
    { id: 'coffee', name: 'Buy Me a Coffee', icon: GiftIcon },
    { id: 'feedback', name: 'Feedback', icon: StarIcon },
    { id: 'connect', name: 'Connect With Me', icon: HeartIcon },
  ];

  const scrollToSection = (sectionId) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center">
                <HeartIconSolid className="h-8 w-8 text-red-500 mr-3" />
                Support Me
              </h1>
              <p className="mt-2 text-gray-600 dark:text-gray-400">
                Thank you for using Finlogy! Your support means the world to me.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Pills */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-wrap gap-2 mb-8">
          {sections.map((section) => {
            const Icon = section.icon;
            return (
              <button
                key={section.id}
                onClick={() => scrollToSection(section.id)}
                className={`
                  flex items-center px-4 py-2 rounded-full text-sm font-medium transition-all duration-200
                  ${activeSection === section.id
                    ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700'
                    : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700'
                  }
                `}
              >
                <Icon className="h-4 w-4 mr-2" />
                {section.name}
              </button>
            );
          })}
        </div>

        {/* Content Sections */}
        <div className="space-y-12">
          {/* About Me Section */}
          <section id="about" className="scroll-mt-24">
            <AboutMe />
          </section>

          {/* Buy Me a Coffee Section */}
          <section id="coffee" className="scroll-mt-24">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 flex items-center justify-center">
                <GiftIcon className="h-6 w-6 mr-2" />
                Buy Me a Coffee
              </h2>
              <p className="text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
                If you find Finlogy helpful and would like to support its development, 
                consider buying me a coffee! Every contribution helps keep the project running.
              </p>
            </div>
            <BuyMeCoffeeCard />
          </section>

          {/* Feedback Section */}
          <section id="feedback" className="scroll-mt-24">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 flex items-center justify-center">
                <StarIcon className="h-6 w-6 mr-2" />
                Your Feedback Matters
              </h2>
              <p className="text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
                Help me improve Finlogy by sharing your thoughts and rating your experience. 
                Your feedback drives the future development of this application.
              </p>
            </div>
            <FeedbackForm />
          </section>

          {/* Connect With Me Section */}
          <section id="connect" className="scroll-mt-24">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 flex items-center justify-center">
                <HeartIcon className="h-6 w-6 mr-2" />
                Connect With Me
              </h2>
              <p className="text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
                Let's stay connected! Follow me on social media for updates, tips, and behind-the-scenes content.
              </p>
            </div>
            <SocialMediaCards />
          </section>
        </div>

        {/* Footer Message */}
        <div className="mt-16 text-center py-8 border-t border-gray-200 dark:border-gray-700">
          <p className="text-gray-600 dark:text-gray-400">
            Thank you for being part of the Finlogy community! 🚀
          </p>
        </div>
      </div>
    </div>
  );
};

export default SupportMe;
