import React, { useState } from 'react';
import { 
  ArrowTopRightOnSquareIcon,
  ChatBubbleLeftRightIcon,
  CodeBracketIcon,
  EnvelopeIcon
} from '@heroicons/react/24/outline';

const SocialMediaCards = () => {
  const [hoveredCard, setHoveredCard] = useState(null);

  const socialLinks = [
    {
      id: 'github',
      name: 'GitHub',
      description: 'Check out my code and contribute to projects',
      url: 'https://github.com/jeetver1809',
      icon: CodeBracketIcon,
      color: 'from-gray-700 to-gray-900',
      hoverColor: 'hover:from-gray-600 hover:to-gray-800',
      textColor: 'text-white',
      bgPattern: '🐙'
    },
    {
      id: 'discord',
      name: 'Discord',
      description: 'Join our community for real-time discussions',
      url: 'https://discord.com/users/872817963659587606',

      icon: ChatBubbleLeftRightIcon,
      color: 'from-indigo-500 to-purple-600',
      hoverColor: 'hover:from-indigo-400 hover:to-purple-500',
      textColor: 'text-white',
      bgPattern: '💬'
    },
    {
      id: 'twitter',
      name: 'X (Twitter)',
      description: 'Follow for updates and tech insights',
      url: 'https://x.com/JeetVerma_1809',
      icon: ArrowTopRightOnSquareIcon,
      color: 'from-blue-400 to-blue-600',
      hoverColor: 'hover:from-blue-300 hover:to-blue-500',
      textColor: 'text-white',
      bgPattern: '🐦'
    },
    {
      id: 'email',
      name: 'Email',
      description: 'Reach out directly for collaborations',
      url: 'mailto:jeetverma1809@gmail.com',
      icon: EnvelopeIcon,
      color: 'from-green-500 to-teal-600',
      hoverColor: 'hover:from-green-400 hover:to-teal-500',
      textColor: 'text-white',
      bgPattern: '📧'
    },
    {
      id: 'linkedin',
      name: 'LinkedIn',
      description: 'Connect professionally and network',
      url: 'https://www.linkedin.com/in/jeet-verma-9734a01a7/',
      icon: ArrowTopRightOnSquareIcon,
      color: 'from-blue-600 to-blue-800',
      hoverColor: 'hover:from-blue-500 hover:to-blue-700',
      textColor: 'text-white',
      bgPattern: '💼'
    },
    {
      id: 'portfolio',
      name: 'Portfolio',
      description: 'Explore my work and projects',
      url: 'https://jeetver1809.github.io/jeet-s-Den-porfolio/index.html',
      icon: CodeBracketIcon,
      color: 'from-purple-500 to-pink-600',
      hoverColor: 'hover:from-purple-400 hover:to-pink-500',
      textColor: 'text-white',
      bgPattern: '🎨'
    }
  ];

  const handleCardClick = (url) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="max-w-6xl mx-auto">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {socialLinks.map((social) => {
          const Icon = social.icon;
          const isHovered = hoveredCard === social.id;
          
          return (
            <div
              key={social.id}
              className={`
                relative group cursor-pointer transform transition-all duration-300 ease-in-out
                ${isHovered ? 'scale-105 z-10' : 'hover:scale-102'}
              `}
              onMouseEnter={() => setHoveredCard(social.id)}
              onMouseLeave={() => setHoveredCard(null)}
              onClick={() => handleCardClick(social.url)}
            >
              {/* Card */}
              <div className={`
                relative overflow-hidden rounded-xl p-6 h-40
                bg-gradient-to-br ${social.color} ${social.hoverColor}
                shadow-lg transition-all duration-300 ease-in-out
                ${isHovered ? 'shadow-2xl' : 'group-hover:shadow-xl'}
                border border-white/10
              `}>
                {/* Background Pattern */}
                <div className="absolute top-2 right-2 text-4xl opacity-20">
                  {social.bgPattern}
                </div>
                
                {/* Animated Background Gradient */}
                <div className={`
                  absolute inset-0 bg-gradient-to-br from-white/10 to-transparent opacity-0
                  transition-opacity duration-300 ease-in-out
                  ${isHovered ? 'opacity-100' : 'group-hover:opacity-50'}
                `} />

                {/* Content */}
                <div className="relative z-10 h-full flex flex-col justify-between">
                  {/* Header */}
                  <div className="flex items-center justify-between">
                    <div className={`
                      p-2 rounded-lg bg-white/20 backdrop-blur-sm
                      transition-all duration-300 ease-in-out
                      ${isHovered ? 'scale-110 bg-white/30' : ''}
                    `}>
                      <Icon className="h-6 w-6 text-white" />
                    </div>
                    <ArrowTopRightOnSquareIcon className={`
                      h-5 w-5 text-white/70 transition-all duration-300 ease-in-out
                      ${isHovered ? 'text-white translate-x-1 -translate-y-1' : ''}
                    `} />
                  </div>

                  {/* Content */}
                  <div>
                    <h3 className={`text-xl font-bold ${social.textColor} mb-2`}>
                      {social.name}
                    </h3>
                    <p className={`text-sm ${social.textColor} opacity-90 leading-relaxed`}>
                      {social.description}
                    </p>
                  </div>
                </div>

                {/* Hover Effect Overlay */}
                <div className={`
                  absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0
                  transition-opacity duration-300 ease-in-out
                  ${isHovered ? 'opacity-100' : ''}
                `} />
              </div>

              {/* Glow Effect */}
              <div className={`
                absolute inset-0 rounded-xl blur-xl opacity-0 transition-opacity duration-300 ease-in-out
                bg-gradient-to-br ${social.color}
                ${isHovered ? 'opacity-30' : ''}
                -z-10
              `} />
            </div>
          );
        })}
      </div>

      {/* Call to Action */}
      <div className="mt-12 text-center">
        <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg p-6 border border-blue-200 dark:border-blue-700/50">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            Let's Connect!
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            I'm always excited to connect with fellow developers, users, and anyone interested in fintech. 
            Don't hesitate to reach out!
          </p>
          <div className="flex flex-wrap justify-center gap-2 text-sm text-gray-500 dark:text-gray-400">
            <span>💡 Collaboration</span>
            <span>•</span>
            <span>🤝 Networking</span>
            <span>•</span>
            <span>💬 Feedback</span>
            <span>•</span>
            <span>🚀 Opportunities</span>
          </div>
        </div>
      </div>

     
    </div>
  );
};

export default SocialMediaCards;
