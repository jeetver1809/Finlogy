import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { authService } from '../services/authService';
import toast from 'react-hot-toast';

const AuthContext = createContext();

const initialState = {
  user: null,
  token: localStorage.getItem('token'),
  isLoading: true,
  isAuthenticated: false,
};

const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN_START':
      return {
        ...state,
        isLoading: true,
      };
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        isLoading: false,
      };
    case 'LOGIN_FAILURE':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
      };
    case 'LOGOUT':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
      };
    case 'UPDATE_USER':
      return {
        ...state,
        user: { ...state.user, ...action.payload },
      };
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
      };
    default:
      return state;
  }
};

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Check if user is authenticated on app load
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          const response = await authService.getProfile();
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: {
              user: response.data,
              token,
            },
          });
        } catch (error) {
          localStorage.removeItem('token');
          dispatch({ type: 'LOGIN_FAILURE' });
        }
      } else {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    };

    checkAuth();
  }, []);

  const login = async (credentials, options = {}) => {
    try {
      dispatch({ type: 'LOGIN_START' });
      const response = await authService.login(credentials);

      localStorage.setItem('token', response.data.token);

      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user: response.data,
          token: response.data.token,
        },
      });

      if (!options.suppressSuccessToast) {
        toast.success('Login successful!');
      }
      return { success: true };
    } catch (error) {
      dispatch({ type: 'LOGIN_FAILURE' });
      const message = error.response?.data?.message || 'Login failed';

      // Only show toast if not suppressed (for custom error handling)
      if (!options.suppressErrorToast) {
        toast.error(message);
      }

      return { success: false, message };
    }
  };

  const register = async (userData) => {
    try {
      dispatch({ type: 'LOGIN_START' });
      const response = await authService.register(userData);
      
      localStorage.setItem('token', response.data.token);
      
      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user: response.data,
          token: response.data.token,
        },
      });
      
      toast.success('Registration successful!');
      return { success: true };
    } catch (error) {
      dispatch({ type: 'LOGIN_FAILURE' });
      const message = error.response?.data?.message || 'Registration failed';
      toast.error(message);
      return { success: false, message };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    dispatch({ type: 'LOGOUT' });
    toast.success('Logged out successfully');
  };

  const updateUser = (userData) => {
    dispatch({ type: 'UPDATE_USER', payload: userData });
  };

  const handleOAuthCallback = async (token, retryCount = 0) => {
    const MAX_RETRIES = 3;
    const RETRY_DELAY = 1000; // 1 second

    try {
      dispatch({ type: 'LOGIN_START' });

      // Store the token
      localStorage.setItem('token', token);

      // Get user profile with the token
      const response = await authService.getProfile();

      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user: response.data,
          token,
        },
      });

      return { success: true };
    } catch (error) {
      // If we get a 429 (Too Many Requests) and haven't exceeded max retries
      if (error.response?.status === 429 && retryCount < MAX_RETRIES) {
        // Wait for an increasing delay before retrying (exponential backoff)
        const delay = RETRY_DELAY * Math.pow(2, retryCount);
        await new Promise(resolve => setTimeout(resolve, delay));
        
        // Retry the request
        return handleOAuthCallback(token, retryCount + 1);
      }

      // If we've exhausted retries or it's a different error
      dispatch({ type: 'LOGIN_FAILURE' });
      localStorage.removeItem('token');
      
      let message = 'OAuth authentication failed';
      if (error.response?.status === 429) {
        message = 'Too many requests. Please wait a moment and try again.';
      } else if (error.response?.data?.message) {
        message = error.response.data.message;
      }
      
      throw new Error(message);
    }
  };

  const initiateOAuth = (provider) => {
  const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';
  window.location.href = `${baseUrl}/auth/${provider}`;
};

  const value = {
    ...state,
    login,
    register,
    logout,
    updateUser,
    handleOAuthCallback,
    initiateOAuth,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
