# OAuth Setup Instructions

## Quick Setup Guide

### 1. **Install Dependencies** ✅
All required dependencies have been installed:
- Backend: `passport`, `passport-google-oauth20`, `passport-microsoft`, `express-session`
- Frontend: `react-router-dom`

### 2. **Configure OAuth Providers**

#### Google OAuth Setup
1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Go to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth 2.0 Client IDs"
5. Configure:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:5001/api/auth/google/callback`
6. Copy Client ID and Client Secret

#### Microsoft OAuth Setup
1. Visit [Azure Portal](https://portal.azure.com/)
2. Go to "Azure Active Directory" > "App registrations"
3. Click "New registration"
4. Configure:
   - Name: Your app name
   - Redirect URI: `http://localhost:5001/api/auth/microsoft/callback`
5. Go to "Certificates & secrets" > "New client secret"
6. Copy Application (client) ID and Client Secret

### 3. **Update Environment Variables**
Edit `backend/.env` and add your OAuth credentials:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here

# Microsoft OAuth  
MICROSOFT_CLIENT_ID=your-microsoft-client-id-here
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret-here
```

### 4. **Test the Implementation**
1. Start backend: `cd backend && npm run dev`
2. Start frontend: `cd frontend && npm run dev`
3. Open `http://localhost:5173`
4. Try OAuth buttons on login/register pages

### 5. **Troubleshooting**

#### Common Issues:
- **"OAuth client not found"**: Check client IDs in .env file
- **"Redirect URI mismatch"**: Verify callback URLs in OAuth provider settings
- **"Invalid client secret"**: Regenerate and update client secret

#### Debug Steps:
1. Check browser console for errors
2. Verify backend server is running on port 5001
3. Ensure MongoDB is connected
4. Check OAuth provider dashboard for error logs

### 6. **Production Deployment**
When deploying to production:
1. Update OAuth callback URLs to your production domain
2. Use environment variables for sensitive data
3. Enable HTTPS for OAuth redirects
4. Update CORS settings for production domain

---

**Status**: Ready for OAuth provider configuration
**Next Step**: Add your OAuth credentials to backend/.env file
