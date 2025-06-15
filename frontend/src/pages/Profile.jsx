import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useCurrency } from '../context/CurrencyContext';
import { useTheme } from '../context/ThemeContext';
import { authService } from '../services/authService';
import CurrencySelector from '../components/ui/CurrencySelector';
import AvatarDisplay from '../components/ui/AvatarDisplay';
import AvatarSelector from '../components/ui/AvatarSelector';
import { ArrowRightOnRectangleIcon, UserCircleIcon, EyeIcon, EyeSlashIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Profile = () => {
  const { user, updateUser, logout } = useAuth();
  const { currency } = useCurrency();
  const { theme, toggleTheme } = useTheme();
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: user?.name || '',
    email: user?.email || '',
  });

  // Avatar state
  const [avatarLoading, setAvatarLoading] = useState(false);

  // Password change state
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState({});
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleProfileUpdate = async (e) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }

    try {
      setIsLoading(true);
      const response = await authService.updateProfile({
        name: formData.name,
      });

      updateUser(response.data);
      toast.success('Profile updated successfully!');
    } catch (error) {
      console.error('Error updating profile:', error);
      toast.error('Failed to update profile');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      logout();
    }
  };

  // Avatar mapping for user-friendly names
  const avatarNames = {
    'boy1.png': 'Boy Avatar 1',
    'boy2.png': 'Boy Avatar 2',
    'girl1.png': 'Girl Avatar 1',
    'girl2.png': 'Girl Avatar 2',
  };

  const handleAvatarSelect = async (avatarId) => {
    try {
      setAvatarLoading(true);
      const response = await authService.updateProfile({
        avatar: avatarId,
      });

      updateUser(response.data);
      toast.success('Avatar updated successfully!');
    } catch (error) {
      console.error('Error updating avatar:', error);
      toast.error('Failed to update avatar');
    } finally {
      setAvatarLoading(false);
    }
  };

  // Password validation function
  const validatePassword = (password) => {
    const errors = [];
    if (password.length < 6) {
      errors.push('Password must be at least 6 characters long');
    }
    if (!/(?=.*[a-z])/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!/(?=.*[A-Z])/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!/(?=.*\d)/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    return errors;
  };

  // Password form handlers
  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({
      ...prev,
      [name]: value,
    }));

    // Clear errors when user starts typing
    if (passwordErrors[name]) {
      setPasswordErrors(prev => ({
        ...prev,
        [name]: '',
      }));
    }

    // Real-time validation for confirm password
    if (name === 'confirmPassword' && passwordData.newPassword && value !== passwordData.newPassword) {
      setPasswordErrors(prev => ({
        ...prev,
        confirmPassword: 'Passwords do not match',
      }));
    } else if (name === 'confirmPassword' && passwordData.newPassword && value === passwordData.newPassword) {
      setPasswordErrors(prev => ({
        ...prev,
        confirmPassword: '',
      }));
    }
  };

  const togglePasswordVisibility = (field) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field],
    }));
  };

  const validatePasswordForm = () => {
    const errors = {};

    if (!passwordData.currentPassword) {
      errors.currentPassword = 'Current password is required';
    }

    if (!passwordData.newPassword) {
      errors.newPassword = 'New password is required';
    } else {
      const passwordValidationErrors = validatePassword(passwordData.newPassword);
      if (passwordValidationErrors.length > 0) {
        errors.newPassword = passwordValidationErrors[0]; // Show first error
      }
    }

    if (!passwordData.confirmPassword) {
      errors.confirmPassword = 'Please confirm your new password';
    } else if (passwordData.newPassword !== passwordData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    setPasswordErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();

    if (!validatePasswordForm()) {
      toast.error('Please fix the errors in the form');
      return;
    }

    if (!window.confirm('Are you sure you want to change your password?')) {
      return;
    }

    try {
      setPasswordLoading(true);
      await authService.changePassword({
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword,
      });

      // Reset form on success
      setPasswordData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
      setPasswordErrors({});

      toast.success('Password changed successfully!');
    } catch (error) {
      console.error('Error changing password:', error);
      const message = error.response?.data?.message || 'Failed to change password';
      toast.error(message);
    } finally {
      setPasswordLoading(false);
    }
  };

  return (
    <div className="p-8">
      <div className="max-w-2xl mx-auto">
        {/* Profile Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-4">
            <AvatarDisplay
              avatar={user?.avatar}
              name={user?.name}
              size="2xl"
              className="shadow-lg"
            />
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Profile Settings</h1>
              <p className="text-gray-600 dark:text-gray-400">Manage your account preferences and settings</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 px-4 py-2 bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800 text-white rounded-md transition-colors"
            title="Logout"
          >
            <ArrowRightOnRectangleIcon className="h-5 w-5" />
            <span>Logout</span>
          </button>
        </div>

        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg p-6 border border-blue-200 dark:border-blue-800">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Quick Actions</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl mb-2">💰</div>
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Current Currency</p>
                <p className="text-lg font-bold text-blue-600 dark:text-blue-400">{currency}</p>
              </div>
              <div className="text-center">
                <div className="text-2xl mb-2">🎨</div>
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Current Theme</p>
                <p className="text-lg font-bold text-blue-600 dark:text-blue-400">{theme.charAt(0).toUpperCase() + theme.slice(1)}</p>
              </div>
              <div className="text-center">
                <div className="text-2xl mb-2">📅</div>
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Member Since</p>
                <p className="text-lg font-bold text-blue-600 dark:text-blue-400">
                  {user?.createdAt ? new Date(user.createdAt).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }) : 'N/A'}
                </p>
              </div>
            </div>
          </div>

          {/* Profile Information */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <UserCircleIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Profile Information</h2>
            </div>

            <form onSubmit={handleProfileUpdate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                  placeholder="Enter your full name"
                  disabled={isLoading}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-50 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed"
                  disabled
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Email cannot be changed</p>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800 text-white px-4 py-2 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 transition-colors"
                >
                  {isLoading ? 'Updating...' : 'Update Profile'}
                </button>
              </div>
            </form>
          </div>

          {/* Avatar Selection */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <span className="text-2xl">🎭</span>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Avatar Selection</h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Choose an avatar to personalize your profile. Your selected avatar will appear in the navigation bar and throughout the application.
            </p>

            <div className="flex flex-col lg:flex-row lg:items-start lg:space-x-8">
              {/* Current Avatar Display */}
              <div className="mb-6 lg:mb-0">
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Current Avatar</h3>
                <div className="flex items-center space-x-4">
                  <AvatarDisplay
                    avatar={user?.avatar}
                    name={user?.name}
                    size="xl"
                    className="shadow-md"
                  />
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {user?.avatar ? `Selected: ${avatarNames[user.avatar] || user.avatar}` : 'No avatar selected'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      This is how your avatar appears to others
                    </p>
                  </div>
                </div>
              </div>

              {/* Avatar Selector */}
              <div className="flex-1">
                <AvatarSelector
                  currentAvatar={user?.avatar}
                  onAvatarSelect={handleAvatarSelect}
                  isLoading={avatarLoading}
                  className="w-full"
                />
              </div>
            </div>
          </div>

          {/* Currency Preferences */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <span className="text-2xl">💰</span>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Currency Preferences</h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Select your preferred currency for displaying amounts throughout the application.
            </p>

            <div className="max-w-xs">
              <CurrencySelector showLabel={true} />
            </div>

            <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/50 rounded-md border border-blue-200 dark:border-blue-800">
              <p className="text-sm text-blue-800 dark:text-blue-300">
                <strong>Current Currency:</strong> {currency}
              </p>
              <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
                Your currency preference is automatically saved and will be used across all pages.
              </p>
            </div>
          </div>

          {/* Theme Preferences */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <span className="text-2xl">🎨</span>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Theme Preferences</h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Choose your preferred theme for the application interface.
            </p>

            <div className="flex items-center space-x-4">
              <button
                onClick={toggleTheme}
                className={`
                  px-4 py-2 rounded-md border transition-colors
                  ${theme === 'light'
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                  }
                `}
              >
                Light Theme
              </button>
              <button
                onClick={toggleTheme}
                className={`
                  px-4 py-2 rounded-md border transition-colors
                  ${theme === 'dark'
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                  }
                `}
              >
                Dark Theme
              </button>
            </div>

            <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-md border border-gray-200 dark:border-gray-600">
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>Current Theme:</strong> {theme.charAt(0).toUpperCase() + theme.slice(1)}
              </p>
            </div>
          </div>

          {/* Security Settings - Password Change */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <ShieldCheckIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Security Settings</h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Change your password to keep your account secure. Make sure to use a strong password.
            </p>

            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              {/* Current Password */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Current Password *
                </label>
                <div className="relative">
                  <input
                    type={showPasswords.current ? 'text' : 'password'}
                    name="currentPassword"
                    value={passwordData.currentPassword}
                    onChange={handlePasswordChange}
                    className={`w-full pr-10 px-3 py-2 border rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors ${
                      passwordErrors.currentPassword ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                    }`}
                    placeholder="Enter your current password"
                    disabled={passwordLoading}
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('current')}
                    className="absolute right-3 top-2 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                    disabled={passwordLoading}
                  >
                    {showPasswords.current ? (
                      <EyeSlashIcon className="h-5 w-5" />
                    ) : (
                      <EyeIcon className="h-5 w-5" />
                    )}
                  </button>
                </div>
                {passwordErrors.currentPassword && (
                  <p className="text-red-500 dark:text-red-400 text-sm mt-1">{passwordErrors.currentPassword}</p>
                )}
              </div>

              {/* New Password */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  New Password *
                </label>
                <div className="relative">
                  <input
                    type={showPasswords.new ? 'text' : 'password'}
                    name="newPassword"
                    value={passwordData.newPassword}
                    onChange={handlePasswordChange}
                    className={`w-full pr-10 px-3 py-2 border rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors ${
                      passwordErrors.newPassword ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                    }`}
                    placeholder="Enter your new password"
                    disabled={passwordLoading}
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('new')}
                    className="absolute right-3 top-2 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                    disabled={passwordLoading}
                  >
                    {showPasswords.new ? (
                      <EyeSlashIcon className="h-5 w-5" />
                    ) : (
                      <EyeIcon className="h-5 w-5" />
                    )}
                  </button>
                </div>
                {passwordErrors.newPassword && (
                  <p className="text-red-500 dark:text-red-400 text-sm mt-1">{passwordErrors.newPassword}</p>
                )}
                <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                  <p className="mb-2">Password requirements:</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className={`flex items-center space-x-1 ${passwordData.newPassword.length >= 6 ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500'}`}>
                      <span className={`w-2 h-2 rounded-full ${passwordData.newPassword.length >= 6 ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`}></span>
                      <span>6+ characters</span>
                    </div>
                    <div className={`flex items-center space-x-1 ${/(?=.*[a-z])/.test(passwordData.newPassword) ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500'}`}>
                      <span className={`w-2 h-2 rounded-full ${/(?=.*[a-z])/.test(passwordData.newPassword) ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`}></span>
                      <span>Lowercase</span>
                    </div>
                    <div className={`flex items-center space-x-1 ${/(?=.*[A-Z])/.test(passwordData.newPassword) ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500'}`}>
                      <span className={`w-2 h-2 rounded-full ${/(?=.*[A-Z])/.test(passwordData.newPassword) ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`}></span>
                      <span>Uppercase</span>
                    </div>
                    <div className={`flex items-center space-x-1 ${/(?=.*\d)/.test(passwordData.newPassword) ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500'}`}>
                      <span className={`w-2 h-2 rounded-full ${/(?=.*\d)/.test(passwordData.newPassword) ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`}></span>
                      <span>Number</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Confirm New Password */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm New Password *
                </label>
                <div className="relative">
                  <input
                    type={showPasswords.confirm ? 'text' : 'password'}
                    name="confirmPassword"
                    value={passwordData.confirmPassword}
                    onChange={handlePasswordChange}
                    className={`w-full pr-10 px-3 py-2 border rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors ${
                      passwordErrors.confirmPassword ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                    }`}
                    placeholder="Confirm your new password"
                    disabled={passwordLoading}
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('confirm')}
                    className="absolute right-3 top-2 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                    disabled={passwordLoading}
                  >
                    {showPasswords.confirm ? (
                      <EyeSlashIcon className="h-5 w-5" />
                    ) : (
                      <EyeIcon className="h-5 w-5" />
                    )}
                  </button>
                </div>
                {passwordErrors.confirmPassword && (
                  <p className="text-red-500 dark:text-red-400 text-sm mt-1">{passwordErrors.confirmPassword}</p>
                )}
              </div>

              {/* Submit Button */}
              <div className="pt-4">
                <button
                  type="submit"
                  disabled={passwordLoading}
                  className="bg-green-600 hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800 text-white px-6 py-2 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 transition-colors"
                >
                  {passwordLoading ? 'Changing Password...' : 'Change Password'}
                </button>
              </div>
            </form>

            {/* Security Tips */}
            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/50 rounded-md border border-blue-200 dark:border-blue-800">
              <h4 className="text-sm font-medium text-blue-800 dark:text-blue-300 mb-2">🔒 Security Tips</h4>
              <ul className="text-xs text-blue-700 dark:text-blue-400 space-y-1">
                <li>• Use a unique password that you don't use elsewhere</li>
                <li>• Consider using a password manager to generate and store strong passwords</li>
                <li>• Never share your password with anyone</li>
                <li>• Change your password regularly for better security</li>
              </ul>
            </div>
          </div>

          {/* Account Information */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <span className="text-2xl">ℹ️</span>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Account Information</h2>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Account Created:</span>
                <span className="text-gray-900 dark:text-white">
                  {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Email Verified:</span>
                <span className={`${user?.isEmailVerified ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                  {user?.isEmailVerified ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">User ID:</span>
                <span className="text-gray-900 dark:text-white font-mono text-xs">{user?._id}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
