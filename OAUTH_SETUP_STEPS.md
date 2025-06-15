# 🔐 OAuth Setup - Fix Authentication Errors

## Current Issue
- Google OAuth Error: "The OAuth client was not found. Error 401: invalid_client"
- Microsoft OAuth Error: "unauthorized_client: The client does not exist or is not enabled for consumers"

## Root Cause
The `.env` file contains placeholder OAuth credentials instead of real ones from Google and Microsoft.

---

## 🚀 SOLUTION: Set Up Real OAuth Credentials

### **STEP 1: Google OAuth Setup (5 minutes)**

1. **Open Google Cloud Console**: https://console.cloud.google.com/

2. **Create/Select Project**:
   - Click project dropdown → "New Project" or select existing
   - Project name: "Personal Finance Tracker"

3. **Enable APIs**:
   - Go to "APIs & Services" → "Library"
   - Search "Google+ API" → Click → "Enable"

4. **Configure OAuth Consent Screen**:
   - Go to "APIs & Services" → "OAuth consent screen"
   - User Type: "External" → Create
   - App name: "Personal Finance Tracker"
   - User support email: Your email
   - Developer contact: Your email
   - Save and Continue → Save and Continue → Save and Continue

5. **Create OAuth Credentials**:
   - Go to "APIs & Services" → "Credentials"
   - "Create Credentials" → "OAuth 2.0 Client IDs"
   - Application type: "Web application"
   - Name: "Personal Finance Tracker"
   - Authorized redirect URIs: `http://localhost:5001/api/auth/google/callback`
   - Click "Create"

6. **Copy Credentials**:
   - Copy "Client ID" (starts with numbers, ends with .googleusercontent.com)
   - Copy "Client Secret" (random string)

---

### **STEP 2: Microsoft OAuth Setup (5 minutes)**

1. **Open Azure Portal**: https://portal.azure.com/

2. **Navigate to App Registrations**:
   - Search "Azure Active Directory" → Click
   - Left menu: "App registrations" → "New registration"

3. **Register Application**:
   - Name: "Personal Finance Tracker"
   - Supported account types: "Accounts in any organizational directory and personal Microsoft accounts"
   - Redirect URI: 
     - Platform: "Web"
     - URI: `http://localhost:5001/api/auth/microsoft/callback`
   - Click "Register"

4. **Get Application ID**:
   - Copy "Application (client) ID" from overview page

5. **Create Client Secret**:
   - Left menu: "Certificates & secrets"
   - "New client secret"
   - Description: "OAuth Secret"
   - Expires: "24 months"
   - Click "Add"
   - **IMPORTANT**: Copy the "Value" immediately (won't be shown again!)

---

### **STEP 3: Update Environment Variables**

1. **Open**: `backend/.env` file

2. **Replace these lines**:
```env
GOOGLE_CLIENT_ID=your-google-client-id-from-console
GOOGLE_CLIENT_SECRET=your-google-client-secret-from-console

MICROSOFT_CLIENT_ID=your-microsoft-application-client-id-from-azure
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret-from-azure
```

3. **With your actual credentials**:
```env
GOOGLE_CLIENT_ID=123456789-abcdefghijklmnop.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your_actual_google_secret

MICROSOFT_CLIENT_ID=12345678-1234-1234-1234-123456789abc
MICROSOFT_CLIENT_SECRET=your_actual_microsoft_secret
```

---

### **STEP 4: Restart Server**

1. **Stop backend server** (Ctrl+C in terminal)
2. **Restart**: `npm run dev`
3. **Test OAuth buttons** on login page

---

## 🎯 **Expected Result After Setup**

✅ Google button → Redirects to Google login
✅ Microsoft button → Redirects to Microsoft login  
✅ After OAuth → Redirects back to your app dashboard
✅ User logged in successfully

---

## 🚨 **Troubleshooting**

### If Google OAuth still fails:
- Verify redirect URI exactly matches: `http://localhost:5001/api/auth/google/callback`
- Check if Google+ API is enabled
- Ensure OAuth consent screen is configured

### If Microsoft OAuth still fails:
- Verify redirect URI exactly matches: `http://localhost:5001/api/auth/microsoft/callback`
- Check account type supports personal Microsoft accounts
- Ensure client secret hasn't expired

### General Issues:
- Restart backend server after updating .env
- Check browser console for detailed error messages
- Verify backend is running on port 5001

---

## 📞 **Need Help?**

If you encounter issues:
1. Share the exact error message from browser console
2. Confirm which step you completed
3. Check if credentials are correctly copied (no extra spaces)

**Time to complete**: ~10 minutes total
**Difficulty**: Easy (just copy-paste credentials)
