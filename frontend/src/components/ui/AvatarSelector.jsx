import React, { useState } from 'react';
import { CheckIcon } from '@heroicons/react/24/solid';
import toast from 'react-hot-toast';

const AvatarSelector = ({ 
  currentAvatar, 
  onAvatarSelect, 
  isLoading = false,
  className = '' 
}) => {
  const [selectedAvatar, setSelectedAvatar] = useState(currentAvatar || '');
  const [imageErrors, setImageErrors] = useState({});

  // Available avatars
  const avatars = [
    { id: 'boy1.png', name: 'Boy Avatar 1' },
    { id: 'boy2.png', name: 'Boy Avatar 2' },
    { id: 'girl1.png', name: 'Girl Avatar 1' },
    { id: 'girl2.png', name: 'Girl Avatar 2' },
  ];

  const handleAvatarClick = (avatarId) => {
    if (isLoading) return;
    
    setSelectedAvatar(avatarId);
    if (onAvatarSelect) {
      onAvatarSelect(avatarId);
    }
  };

  const handleImageError = (avatarId) => {
    setImageErrors(prev => ({
      ...prev,
      [avatarId]: true
    }));
    toast.error(`Failed to load ${avatarId}`);
  };

  return (
    <div className={`${className}`}>
      <div className="mb-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          Choose Your Avatar
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Select an avatar to personalize your profile
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {avatars.map((avatar) => {
          const isSelected = selectedAvatar === avatar.id;
          const hasError = imageErrors[avatar.id];
          
          return (
            <div
              key={avatar.id}
              className={`relative cursor-pointer transition-all duration-200 ${
                isLoading ? 'opacity-50 cursor-not-allowed' : ''
              }`}
              onClick={() => handleAvatarClick(avatar.id)}
            >
              <div
                className={`relative w-20 h-20 md:w-24 md:h-24 rounded-full overflow-hidden border-4 transition-all duration-200 ${
                  isSelected
                    ? 'border-blue-500 shadow-lg scale-105'
                    : 'border-gray-200 dark:border-gray-600 hover:border-blue-300 hover:scale-102'
                }`}
              >
                {!hasError ? (
                  <img
                    src={`/images/${avatar.id}`}
                    alt={avatar.name}
                    className="w-full h-full object-cover"
                    onError={() => handleImageError(avatar.id)}
                  />
                ) : (
                  <div className="w-full h-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                    <span className="text-gray-500 dark:text-gray-400 text-xs">
                      Error
                    </span>
                  </div>
                )}

                {/* Selection indicator */}
                {isSelected && (
                  <div className="absolute inset-0 bg-blue-500 bg-opacity-20 flex items-center justify-center">
                    <div className="bg-blue-500 rounded-full p-1">
                      <CheckIcon className="w-4 h-4 text-white" />
                    </div>
                  </div>
                )}

                {/* Loading overlay */}
                {isLoading && isSelected && (
                  <div className="absolute inset-0 bg-black bg-opacity-30 flex items-center justify-center">
                    <div className="animate-spin rounded-full h-6 w-6 border-2 border-white border-t-transparent"></div>
                  </div>
                )}
              </div>

              {/* Avatar name */}
              <p className="text-xs text-center mt-2 text-gray-600 dark:text-gray-400">
                {avatar.name}
              </p>
            </div>
          );
        })}
      </div>

      {selectedAvatar && (
        <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
          <p className="text-sm text-blue-700 dark:text-blue-300">
            Selected: {avatars.find(a => a.id === selectedAvatar)?.name}
          </p>
        </div>
      )}
    </div>
  );
};

export default AvatarSelector;
