const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Test route
app.get('/', (req, res) => {
  res.json({ 
    message: 'Security Training API is running!',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    message: 'Server is healthy',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Test database environment
app.get('/api/test', (req, res) => {
  res.json({
    database_url_exists: !!process.env.DATABASE_URL,
    jwt_secret_exists: !!process.env.JWT_SECRET,
    node_env: process.env.NODE_ENV,
    port: PORT
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database URL: ${process.env.DATABASE_URL ? 'Set' : 'Not set'}`);
});

console.log('Server starting...');