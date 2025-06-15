import React, { useState, useEffect } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../context/AuthContext';
import LoadingSpinner from '../../components/ui/LoadingSpinner';
import OAuthButton from '../../components/ui/OAuthButton';
import Logo from '../../components/ui/Logo';
import FormIcon from '../../components/ui/FormIcon';
import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';

// Validation schema
const schema = yup.object({
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup.string().required('Password is required'),
});

const LoginMoneyvine = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(null);
  const [loginError, setLoginError] = useState('');
  const { login, isAuthenticated, isLoading, initiateOAuth } = useAuth();
  const [ref, inView] = useInView({
    threshold: 0.1,
    triggerOnce: true,
  });

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    watch,
  } = useForm({
    resolver: yupResolver(schema),
  });

  // Clear login error when user starts typing
  const watchedFields = watch(['email', 'password']);
  useEffect(() => {
    if (loginError && (watchedFields[0] || watchedFields[1])) {
      setLoginError('');
    }
  }, [watchedFields, loginError]);

  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, []);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const onSubmit = async (data) => {
    console.log('🚀 onSubmit called with data:', data);

    try {
      // Clear any previous error
      setLoginError('');
      console.log('✅ Cleared previous error');

      console.log('📡 Calling login function...');
      const result = await login(data, { suppressErrorToast: true });
      console.log('📥 Login function completed, result:', result);

      // If login failed, show error message
      if (result && !result.success) {
        console.log('❌ Login failed, showing error message');
        setLoginError('Invalid email or password. Please try again.');
        console.log('🔴 Error state set');

        // Focus back to password field for easy correction
        const passwordField = document.querySelector('input[type="password"]');
        if (passwordField) {
          setTimeout(() => passwordField.focus(), 100);
        }
      } else if (result && result.success) {
        console.log('✅ Login successful!');
      } else {
        console.log('⚠️ Unexpected result format:', result);
        setLoginError('Invalid email or password. Please try again.');
      }
    } catch (error) {
      console.error('💥 Login error caught:', error);
      setLoginError('Invalid email or password. Please try again.');
      console.log('🔴 Error state set from catch block');

      // Focus back to password field for easy correction
      const passwordField = document.querySelector('input[type="password"]');
      if (passwordField) {
        setTimeout(() => passwordField.focus(), 100);
      }
    }
  };

  const handleOAuthSignIn = async (provider) => {
    try {
      setOauthLoading(provider);
      await initiateOAuth(provider);
    } catch (error) {
      console.error(`${provider} OAuth error:`, error);
    } finally {
      setOauthLoading(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-blue-900 flex">
      {/* Left Side - Branding & Hero */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 text-white relative overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute inset-0 opacity-10">
          <div className="absolute top-20 left-20 w-32 h-32 bg-white rounded-full blur-3xl"></div>
          <div className="absolute bottom-40 right-20 w-24 h-24 bg-blue-300 rounded-full blur-2xl"></div>
          <div className="absolute top-1/2 left-1/3 w-16 h-16 bg-slate-300 rounded-full blur-xl"></div>
        </div>
        
        {/* Logo */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="relative z-10"
        >
          <Logo size="md" useCustomIcon={true} className="text-white" />
        </motion.div>

        {/* Hero Content */}
        <div className="relative z-10 space-y-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            <h1 className="text-5xl font-bold leading-tight mb-6">
              Your wealth,<br />
              <span className="text-blue-300">Your Identity.</span>
            </h1>
            <p className="text-xl text-slate-100 leading-relaxed">
              Take control of your financial future with Finlogy the intelligent money management platform.
            </p>
          </motion.div>

          {/* 3D Illustration */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1, delay: 0.4 }}
            className="relative"
          >
            <div className="w-80 h-60 mx-auto relative">
              {/* Phone Mockup */}
              <div className="absolute inset-0 bg-gradient-to-br from-slate-600 to-blue-700 rounded-3xl shadow-2xl transform rotate-12 scale-90">
                <div className="p-6 h-full flex flex-col justify-center items-center">
                  <div className="w-16 h-16 bg-white/20 rounded-2xl mb-4 flex items-center justify-center">
                    <FormIcon type="finance" size="lg" className="text-white" />
                  </div>
                  <div className="space-y-2 w-full">
                    <div className="h-2 bg-white/30 rounded w-3/4 mx-auto"></div>
                    <div className="h-2 bg-white/20 rounded w-1/2 mx-auto"></div>
                  </div>
                </div>
              </div>
              
              {/* Card Mockup */}
              <div className="absolute top-8 -right-4 w-32 h-20 bg-gradient-to-r from-blue-400 to-blue-600 rounded-xl shadow-xl transform -rotate-12">
                <div className="p-3 h-full flex flex-col justify-between">
                  <div className="w-8 h-2 bg-white/40 rounded"></div>
                  <div className="space-y-1">
                    <div className="h-1 bg-white/60 rounded w-full"></div>
                    <div className="h-1 bg-white/40 rounded w-2/3"></div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Footer */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 1 }}
          className="relative z-10 text-sm text-slate-200"
        >
          © 2025 Finlogy. All rights reserved.
        </motion.div>
      </div>

      {/* Right Side - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6 }}
          className="w-full max-w-md bg-white rounded-3xl shadow-2xl p-8 lg:p-10"
          ref={ref}
        >
          {/* Mobile Logo */}
          <div className="lg:hidden flex justify-center mb-8">
            <Logo size="lg" useCustomIcon={true} />
          </div>

          <div className="space-y-6">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-2">Login</h2>
              <p className="text-gray-600">Welcome back! Please sign in to your account.</p>
            </div>

            {/* OAuth Button */}
            <OAuthButton
              provider="google"
              onClick={() => handleOAuthSignIn('google')}
              isLoading={oauthLoading === 'google'}
              disabled={oauthLoading !== null}
              className="w-full justify-center py-3 px-4 border border-gray-200 rounded-xl bg-white hover:bg-gray-50 text-gray-700 font-medium shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.02]"
            >
              Continue with Google
            </OAuthButton>

            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-4 bg-white text-gray-500 font-medium">
                  Or sign in with email
                </span>
              </div>
            </div>

            {/* Login Form */}
            <form
              className="space-y-5"
              onSubmit={(e) => {
                e.preventDefault();
                handleSubmit(onSubmit)(e);
              }}
            >
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                  Email*
                </label>
                <input
                  {...register('email')}
                  type="email"
                  autoComplete="email"
                  className={`w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors placeholder-gray-400 ${errors.email ? 'border-red-300 focus:ring-red-500' : 'hover:border-gray-300'}`}
                  placeholder="Enter your email address"
                />
                {errors.email && (
                  <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
                )}
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                  Password*
                </label>
                <div className="relative">
                  <input
                    {...register('password')}
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    className={`w-full px-4 py-3 pr-12 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors placeholder-gray-400 ${errors.password ? 'border-red-300 focus:ring-red-500' : 'hover:border-gray-300'}`}
                    placeholder="Enter password"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 transition-colors"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeSlashIcon className="h-5 w-5" />
                    ) : (
                      <EyeIcon className="h-5 w-5" />
                    )}
                  </button>
                </div>
                {errors.password && (
                  <p className="mt-1 text-sm text-red-600">{errors.password.message}</p>
                )}
              </div>

              <div className="flex items-center justify-between">
                <div className="text-sm">
                  <Link
                    to="/forgot-password"
                    className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
                  >
                    Forgot password? Reset
                  </Link>
                </div>
              </div>

              {/* Login Error Message */}
              {loginError && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.3 }}
                  className="bg-red-50 border border-red-200 rounded-lg p-3"
                >
                  <p className="text-sm text-red-600 font-medium flex items-center">
                    <svg className="w-4 h-4 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                    {loginError}
                  </p>
                </motion.div>
              )}

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold py-3 px-4 rounded-xl transition-all duration-200 hover:scale-[1.02] hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <LoadingSpinner size="sm" className="mr-2" />
                ) : null}
                Login
              </button>
            </form>

            <div className="text-center text-sm text-gray-600">
              Don't have an account?{' '}
              <Link
                to="/register"
                className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
              >
                Sign up here
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default LoginMoneyvine;
