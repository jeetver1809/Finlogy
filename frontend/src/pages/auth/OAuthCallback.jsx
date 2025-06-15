import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import LoadingSpinner from '../../components/ui/LoadingSpinner';
import toast from 'react-hot-toast';

const OAuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { handleOAuthCallback } = useAuth();
  const [isLoading, setIsLoading] = React.useState(true);

  // Only run once when component mounts
  React.useEffect(() => {
    const handleCallback = async () => {
      try {
        const token = searchParams.get('token');
        const error = searchParams.get('error');

        if (error) {
          let errorMessage = 'OAuth authentication failed';
          switch (error) {
            case 'oauth_failed':
              errorMessage = 'OAuth authentication failed. Please try again.';
              break;
            case 'oauth_error':
              errorMessage = 'An error occurred during authentication. Please try again.';
              break;
            default:
              errorMessage = 'Authentication failed. Please try again.';
          }
          
          toast.error(errorMessage);
          navigate('/login');
          setIsLoading(false);
          return;
        }

        if (token) {
          try {
            await handleOAuthCallback(token);
            toast.success('Successfully signed in!');
            navigate('/dashboard');
          } catch (error) {
            console.error('OAuth callback error:', error);
            toast.error('Failed to complete authentication. Please try again.');
            navigate('/login');
          }
        } else {
          toast.error('No authentication token received.');
          navigate('/login');
        }
      } finally {
        setIsLoading(false);
      }
    };

    handleCallback();
  }, []); // Empty dependency array to run only once

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="max-w-md w-full space-y-8 text-center">
          <div>
            <LoadingSpinner size="lg" />
            <h2 className="mt-6 text-2xl font-bold text-gray-900 dark:text-white">
              Completing Sign In...
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Please wait while we complete your authentication.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return null; // Return null after loading state to prevent re-rendering
};

export default OAuthCallback;
