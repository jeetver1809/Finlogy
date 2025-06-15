# Personal Finance Tracker

A comprehensive personal finance tracker built with the MERN stack (MongoDB, Express.js, React, Node.js).

## Features

### Core Features
- 🔐 User authentication and registration system
- 📊 Dashboard with expense overview and summary statistics
- 💰 Add, edit, and delete expense entries with categories
- 📈 Income tracking alongside expenses
- 📅 Monthly/yearly expense analysis with charts and graphs
- 🎯 Budget setting and tracking against actual expenses
- 🔍 Search and filter expenses by date range, category, or amount
- 📄 Export data functionality (CSV/PDF reports)

### UI/UX Features
- 📱 Responsive design (desktop, tablet, mobile)
- 🎨 Clean, intuitive interface with modern design
- 📊 Interactive charts and visualizations
- 🌙 Dark/light theme toggle
- ⚡ Loading states and error handling
- ✨ Smooth animations and transitions

## Tech Stack

- **Frontend**: React 18, Vite, Tailwind CSS, Chart.js
- **Backend**: Node.js, Express.js, JWT Authentication
- **Database**: MongoDB with Mongoose
- **State Management**: React Context API
- **UI Components**: Headless UI, Heroicons

## Quick Start

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (local installation or MongoDB Atlas account)
- npm or yarn

### Automated Setup

#### Option 1: Using Setup Script (Recommended)

**For Windows:**
```bash
setup.bat
```

**For macOS/Linux:**
```bash
chmod +x setup.sh
./setup.sh
```

#### Option 2: Manual Setup

1. Clone the repository
```bash
git clone <repository-url>
cd personal-finance-tracker
```

2. Install dependencies for all packages
```bash
npm run install-deps
```

3. Set up environment variables
```bash
# Backend (.env in backend folder)
cp backend/.env.example backend/.env
# Edit backend/.env with your MongoDB URI and JWT secret

# Frontend (.env in frontend folder)
cp frontend/.env.example frontend/.env
# Edit frontend/.env with your API URL (default: http://localhost:5000/api)
```

4. Configure MongoDB
   - **Local MongoDB:** Make sure MongoDB is running on your system
   - **MongoDB Atlas:** Update `MONGODB_URI` in `backend/.env` with your Atlas connection string

5. Start the development servers
```bash
npm run dev
```

This will start both the backend server (port 5000) and frontend development server (port 5173).

### First Time Setup

1. Open your browser and navigate to `http://localhost:5173`
2. Click "Create a new account" to register
3. Fill in your details and create your account
4. Start tracking your finances!

### Default Ports
- **Frontend (React):** http://localhost:5173
- **Backend (API):** http://localhost:5000
- **API Health Check:** http://localhost:5000/api/health

## Project Structure

```
personal-finance-tracker/
├── backend/                 # Node.js/Express API
│   ├── config/             # Database and environment config
│   ├── controllers/        # Route controllers
│   ├── middleware/         # Authentication and validation middleware
│   ├── models/            # MongoDB schemas
│   ├── routes/            # API routes
│   ├── utils/             # Helper functions
│   └── server.js          # Main server file
├── frontend/              # React application
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Main application pages
│   │   ├── context/       # React Context for state management
│   │   ├── hooks/         # Custom React hooks
│   │   ├── services/      # API service functions
│   │   ├── utils/         # Helper functions
│   │   └── styles/        # CSS and styling files
│   └── public/            # Static assets
└── README.md              # Project documentation
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/profile` - Get user profile

### Expenses
- `GET /api/expenses` - Get all expenses
- `POST /api/expenses` - Create new expense
- `PUT /api/expenses/:id` - Update expense
- `DELETE /api/expenses/:id` - Delete expense

### Income
- `GET /api/income` - Get all income entries
- `POST /api/income` - Create new income entry
- `PUT /api/income/:id` - Update income entry
- `DELETE /api/income/:id` - Delete income entry

### Budgets
- `GET /api/budgets` - Get all budgets
- `POST /api/budgets` - Create new budget
- `PUT /api/budgets/:id` - Update budget
- `DELETE /api/budgets/:id` - Delete budget

### Analytics
- `GET /api/analytics/summary` - Get financial summary
- `GET /api/analytics/monthly` - Get monthly analysis
- `GET /api/analytics/category` - Get category breakdown

## Development

### Available Scripts

**Root level:**
- `npm run dev` - Start both frontend and backend servers
- `npm run server` - Start only the backend server
- `npm run client` - Start only the frontend server
- `npm run build` - Build the frontend for production
- `npm run install-deps` - Install dependencies for all packages

**Backend:**
- `npm start` - Start the production server
- `npm run dev` - Start the development server with nodemon
- `npm test` - Run tests

**Frontend:**
- `npm run dev` - Start the development server
- `npm run build` - Build for production
- `npm run preview` - Preview the production build

### Environment Variables

**Backend (.env):**
```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/finance-tracker
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRE=30d
CLIENT_URL=http://localhost:5173
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

**Frontend (.env):**
```env
VITE_API_URL=http://localhost:5000/api
VITE_APP_NAME=Personal Finance Tracker
VITE_APP_VERSION=1.0.0
```

### Database Setup

**Option 1: Local MongoDB**
1. Install MongoDB on your system
2. Start MongoDB service
3. Use default connection string: `mongodb://localhost:27017/finance-tracker`

**Option 2: MongoDB Atlas (Cloud)**
1. Create a free account at [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create a new cluster
3. Get your connection string
4. Update `MONGODB_URI` in `backend/.env`

### Troubleshooting

**Common Issues:**

1. **Port already in use:**
   - Backend: Change `PORT` in `backend/.env`
   - Frontend: Vite will automatically suggest an alternative port

2. **MongoDB connection failed:**
   - Ensure MongoDB is running (local) or connection string is correct (Atlas)
   - Check firewall settings

3. **CORS errors:**
   - Ensure `CLIENT_URL` in `backend/.env` matches your frontend URL

4. **Build errors:**
   - Clear node_modules and reinstall: `rm -rf node_modules package-lock.json && npm install`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



## Support

If you encounter any issues or have questions:
1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with detailed information about your problem

## Roadmap

- [ ] Expense categories customization
- [ ] Recurring transactions automation
- [ ] Data export/import functionality
- [ ] Mobile app development
- [ ] Advanced analytics and insights
- [ ] Multi-currency support
- [ ] Receipt scanning with OCR
- [ ] Integration with banks and financial institutions
