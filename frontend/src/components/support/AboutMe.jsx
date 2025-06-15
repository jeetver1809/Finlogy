import React from 'react';
import { UserIcon, CodeBracketIcon, HeartIcon, LightBulbIcon } from '@heroicons/react/24/outline';

const AboutMe = () => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-8">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 flex items-center justify-center">
          <UserIcon className="h-6 w-6 mr-2"  />
          About Me
        </h2>
      </div>

      <div className="max-w-4xl mx-auto">
        {/* Profile Section */}
        <div className="flex flex-col md:flex-row items-center md:items-start gap-8 mb-8">
          <div className="flex-shrink-0">
            <div className="w-32 h-32 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
           <div className="relative h-32 w-32 rounded-full  bg-blue p-1">
   <img
    src="/images/jeet.jpg"
    alt="User Profile"
    className="h-full w-full rounded-full object-cover"
  />
</div>




            </div>
          </div>
          
          <div className="flex-1 text-center md:text-left">
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
              Web developer & programmer
            </h3>
            <p className="text-gray-600 dark:text-gray-400 leading-relaxed">
              Finlogy is a passion project built to help people take control of their finances through a beautiful, intuitive interface. As an independent developer, I — Jeet Verma — have poured countless hours into designing, developing, and refining this comprehensive financial management platform.
            </p>
          </div>
        </div>

        {/* Story Cards */}
        <div className="grid md:grid-cols-2 gap-6 mb-8">
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <LightBulbIcon className="h-6 w-6 text-yellow-500 mr-3" />
              <h4 className="text-lg font-semibold text-gray-900 dark:text-white">The Inspiration</h4>
            </div>
            <p className="text-gray-600 dark:text-gray-400 text-sm leading-relaxed">
              Finlogy started as a personal project to solve my own financial tracking challenges. 
              I wanted something simple, beautiful, and powerful - without the complexity of traditional finance software.
            </p>
          </div>

          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <CodeBracketIcon className="h-6 w-6 text-blue-500 mr-3" />
              <h4 className="text-lg font-semibold text-gray-900 dark:text-white">The Technology</h4>
            </div>
            <p className="text-gray-600 dark:text-gray-400 text-sm leading-relaxed">
              Built with modern web technologies including React, Node.js, and MongoDB. 
              I believe in creating fast, responsive, and user-friendly applications that work seamlessly across all devices.
            </p>
          </div>
        </div>

        {/* Mission Statement */}
        <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg p-6 border border-blue-200 dark:border-blue-700/50">
          <div className="flex items-center mb-4">
            <HeartIcon className="h-6 w-6 text-red-500 mr-3" />
            <h4 className="text-lg font-semibold text-gray-900 dark:text-white">My Mission</h4>
          </div>
          <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
            To empower individuals with intuitive financial tools that make money management accessible, 
            enjoyable, and effective. Every feature in Finlogy is designed with real users in mind, 
            focusing on simplicity without sacrificing functionality.
          </p>
        </div>

      
       
      </div>
    </div>
  );
};

export default AboutMe;
