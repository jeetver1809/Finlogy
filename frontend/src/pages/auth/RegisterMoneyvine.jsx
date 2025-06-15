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
  name: yup.string().required('Name is required').min(2, 'Name must be at least 2 characters'),
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup.string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase, and number'),
  confirmPassword: yup.string()
    .required('Please confirm your password')
    .oneOf([yup.ref('password')], 'Passwords must match'),
});

const RegisterMoneyvine = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(null);
  const { register: registerUser, isAuthenticated, isLoading, initiateOAuth } = useAuth();
  const [ref, inView] = useInView({
    threshold: 0.1,
    triggerOnce: true,
  });

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: yupResolver(schema),
  });

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
    await registerUser(data);
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
              Start your<br />
              <span className="text-blue-300">Financial Journey.</span>
            </h1>
            <p className="text-xl text-slate-100 leading-relaxed">
              Join thousands of users who trust Finlogy to manage their finances intelligently.
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

      {/* Right Side - Register Form */}
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
              <h2 className="text-3xl font-bold text-gray-900 mb-2">Create Account</h2>
              <p className="text-gray-600">Join Finlogy and take control of your finances.</p>
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
                  Or create account with email
                </span>
              </div>
            </div>

            {/* Register Form */}
            <form className="space-y-5" onSubmit={handleSubmit(onSubmit)}>
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
                  Full Name*
                </label>
                <input
                  {...register('name')}
                  type="text"
                  autoComplete="name"
                  className={`w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors placeholder-gray-400 ${errors.name ? 'border-red-300 focus:ring-red-500' : 'hover:border-gray-300'}`}
                  placeholder="Enter your full name"
                />
                {errors.name && (
                  <p className="mt-1 text-sm text-red-600">{errors.name.message}</p>
                )}
              </div>

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
                    autoComplete="new-password"
                    className={`w-full px-4 py-3 pr-12 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors placeholder-gray-400 ${errors.password ? 'border-red-300 focus:ring-red-500' : 'hover:border-gray-300'}`}
                    placeholder="Create a strong password"
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

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
                  Confirm Password*
                </label>
                <div className="relative">
                  <input
                    {...register('confirmPassword')}
                    type={showConfirmPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    className={`w-full px-4 py-3 pr-12 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors placeholder-gray-400 ${errors.confirmPassword ? 'border-red-300 focus:ring-red-500' : 'hover:border-gray-300'}`}
                    placeholder="Confirm your password"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 transition-colors"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? (
                      <EyeSlashIcon className="h-5 w-5" />
                    ) : (
                      <EyeIcon className="h-5 w-5" />
                    )}
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="mt-1 text-sm text-red-600">{errors.confirmPassword.message}</p>
                )}
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold py-3 px-4 rounded-xl transition-all duration-200 hover:scale-[1.02] hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <LoadingSpinner size="sm" className="mr-2" />
                ) : null}
                Create Account
              </button>
            </form>

            <div className="text-center text-sm text-gray-600">
              Already have an account?{' '}
              <Link
                to="/login"
                className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
              >
                Sign in here
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default RegisterMoneyvine;
