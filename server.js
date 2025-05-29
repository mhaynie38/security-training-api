const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'http://localhost:5173'],
  credentials: true
}));
app.use(express.json());

// PostgreSQL connection for Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initializeDatabase() {
  const client = await pool.connect();
  
  try {
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        company VARCHAR(255) NOT NULL,
        employee_id VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      )
    `);

    // User progress table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_progress (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        module_id VARCHAR(255) NOT NULL,
        quiz_completed BOOLEAN DEFAULT false,
        quiz_score DECIMAL DEFAULT 0,
        quiz_attempts INTEGER DEFAULT 0,
        quiz_completed_at TIMESTAMP,
        scenarios_completed BOOLEAN DEFAULT false,
        scenarios_score DECIMAL DEFAULT 0,
        scenarios_attempts INTEGER DEFAULT 0,
        scenarios_completed_at TIMESTAMP,
        module_completed BOOLEAN DEFAULT false,
        module_completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, module_id)
      )
    `);

    // Training sessions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS training_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        module_id VARCHAR(255) NOT NULL,
        session_type VARCHAR(50) NOT NULL,
        questions_total INTEGER NOT NULL,
        questions_correct INTEGER NOT NULL,
        score DECIMAL NOT NULL,
        time_spent INTEGER,
        ip_address VARCHAR(45),
        user_agent TEXT,
        completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Certificates table
    await client.query(`
      CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        certificate_id VARCHAR(255) UNIQUE NOT NULL,
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        valid_until TIMESTAMP,
        revoked BOOLEAN DEFAULT false,
        revoked_at TIMESTAMP,
        revoked_reason TEXT
      )
    `);

    // Create indexes
    await client.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_users_employee_id ON users(employee_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_progress_user_module ON user_progress(user_id, module_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_sessions_user ON training_sessions(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_certificates_user ON certificates(user_id)');

    // Create default admin user
    const adminExists = await client.query('SELECT id FROM users WHERE email = $1', ['admin@securitytraining.com']);
    
    if (adminExists.rows.length === 0) {
      const adminPassword = await bcrypt.hash('admin123', 10);
      await client.query(`
        INSERT INTO users (first_name, last_name, email, password_hash, company, employee_id, role)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, ['Admin', 'User', 'admin@securitytraining.com', adminPassword, 'System', 'ADMIN001', 'admin']);
      
      console.log('✓ Admin user created: admin@securitytraining.com / admin123');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  } finally {
    client.release();
  }
}

// Initialize database on startup
initializeDatabase();

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Helper functions
const generateCertificateId = (employeeId) => {
  return `SEC-${employeeId}-${new Date().getFullYear()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
};

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// User Registration
app.post('/api/register', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { firstName, lastName, email, password, company, employeeId } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password || !company || !employeeId) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password and create user
    const passwordHash = await bcrypt.hash(password, 10);
    
    const result = await client.query(`
      INSERT INTO users (first_name, last_name, email, password_hash, company, employee_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, first_name, last_name, email, company, employee_id
    `, [firstName, lastName, email, passwordHash, company, employeeId]);

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        company: user.company,
        employeeId: user.employee_id
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  } finally {
    client.release();
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await client.query('SELECT * FROM users WHERE email = $1 AND is_active = true', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login
    await client.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        company: user.company,
        employeeId: user.employee_id
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  } finally {
    client.release();
  }
});

// Get User Progress
app.get('/api/progress', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const userId = req.user.userId;

    const result = await client.query('SELECT * FROM user_progress WHERE user_id = $1', [userId]);

    const progress = {
      completedQuizzes: [],
      completedScenarios: [],
      completedModules: []
    };

    result.rows.forEach(row => {
      if (row.quiz_completed) {
        progress.completedQuizzes.push(row.module_id);
      }
      if (row.scenarios_completed) {
        progress.completedScenarios.push(row.module_id);
      }
      if (row.module_completed) {
        progress.completedModules.push(row.module_id);
      }
    });

    res.json(progress);
  } catch (error) {
    console.error('Progress fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch progress' });
  } finally {
    client.release();
  }
});

// Update Quiz Progress
app.post('/api/progress/quiz', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const userId = req.user.userId;
    const { moduleId, score, questionsTotal, questionsCorrect, timeSpent } = req.body;
    const passed = score >= 0.8;

    // Insert training session
    await client.query(`
      INSERT INTO training_sessions (user_id, module_id, session_type, questions_total, questions_correct, score, time_spent)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [userId, moduleId, 'quiz', questionsTotal, questionsCorrect, score, timeSpent]);

    // Update progress
    await client.query(`
      INSERT INTO user_progress (user_id, module_id, quiz_completed, quiz_score, quiz_completed_at, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id, module_id) 
      DO UPDATE SET 
        quiz_completed = $3,
        quiz_score = $4,
        quiz_completed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    `, [userId, moduleId, passed, score]);

    // Check if module is complete (both quiz and scenarios done)
    if (passed) {
      const progress = await client.query(`
        SELECT scenarios_completed FROM user_progress 
        WHERE user_id = $1 AND module_id = $2
      `, [userId, moduleId]);

      if (progress.rows.length > 0 && progress.rows[0].scenarios_completed) {
        await client.query(`
          UPDATE user_progress 
          SET module_completed = true, module_completed_at = CURRENT_TIMESTAMP
          WHERE user_id = $1 AND module_id = $2
        `, [userId, moduleId]);
      }
    }

    await client.query('COMMIT');
    res.json({ message: 'Quiz progress updated', passed });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Quiz progress update error:', error);
    res.status(500).json({ error: 'Failed to update quiz progress' });
  } finally {
    client.release();
  }
});

// Update Scenario Progress
app.post('/api/progress/scenarios', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const userId = req.user.userId;
    const { moduleId, score, questionsTotal, questionsCorrect, timeSpent } = req.body;
    const passed = score >= 0.8;

    // Insert training session
    await client.query(`
      INSERT INTO training_sessions (user_id, module_id, session_type, questions_total, questions_correct, score, time_spent)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [userId, moduleId, 'scenario', questionsTotal, questionsCorrect, score, timeSpent]);

    // Update progress
    await client.query(`
      INSERT INTO user_progress (user_id, module_id, scenarios_completed, scenarios_score, scenarios_completed_at, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id, module_id) 
      DO UPDATE SET 
        scenarios_completed = $3,
        scenarios_score = $4,
        scenarios_completed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    `, [userId, moduleId, passed, score]);

    // Check if module is complete (both quiz and scenarios done)
    if (passed) {
      const progress = await client.query(`
        SELECT quiz_completed FROM user_progress 
        WHERE user_id = $1 AND module_id = $2
      `, [userId, moduleId]);

      if (progress.rows.length > 0 && progress.rows[0].quiz_completed) {
        await client.query(`
          UPDATE user_progress 
          SET module_completed = true, module_completed_at = CURRENT_TIMESTAMP
          WHERE user_id = $1 AND module_id = $2
        `, [userId, moduleId]);

        // Check if all modules complete and issue certificate
        const moduleCount = await client.query(`
          SELECT COUNT(*) as completed FROM user_progress 
          WHERE user_id = $1 AND module_completed = true
        `, [userId]);

        if (moduleCount.rows[0].completed >= 7) { // All 7 modules
          // Check if certificate already exists
          const existingCert = await client.query('SELECT id FROM certificates WHERE user_id = $1', [userId]);
          
          if (existingCert.rows.length === 0) {
            const user = await client.query('SELECT employee_id FROM users WHERE id = $1', [userId]);
            const certificateId = generateCertificateId(user.rows[0].employee_id);
            const validUntil = new Date();
            validUntil.setFullYear(validUntil.getFullYear() + 2);

            await client.query(`
              INSERT INTO certificates (user_id, certificate_id, valid_until)
              VALUES ($1, $2, $3)
            `, [userId, certificateId, validUntil]);
          }
        }
      }
    }

    await client.query('COMMIT');
    res.json({ message: 'Scenario progress updated', passed });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Scenario progress update error:', error);
    res.status(500).json({ error: 'Failed to update scenario progress' });
  } finally {
    client.release();
  }
});

// Get User Certificate
app.get('/api/certificate', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const userId = req.user.userId;

    const result = await client.query(`
      SELECT c.certificate_id, c.issued_at, c.valid_until, 
             u.first_name, u.last_name, u.company, u.employee_id
      FROM certificates c
      JOIN users u ON c.user_id = u.id
      WHERE c.user_id = $1 AND c.revoked = false
    `, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Certificate fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch certificate' });
  } finally {
    client.release();
  }
});

// Admin endpoints
app.get('/api/admin/stats', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const stats = await client.query(`
      SELECT 
        COUNT(DISTINCT u.id) as total_users,
        COUNT(DISTINCT c.id) as total_certificates,
        COALESCE(AVG(ts.score), 0) as average_score,
        COUNT(ts.id) as total_sessions
      FROM users u
      LEFT JOIN certificates c ON c.user_id = u.id
      LEFT JOIN training_sessions ts ON ts.user_id = u.id
    `);

    res.json(stats.rows[0]);
  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  } finally {
    client.release();
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Security Training API running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'Not configured'}`);
});

module.exports = app;