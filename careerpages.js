// careerpages.js - Career pages management module

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { authenticateToken } = require('./auth');
const XLSX = require('xlsx');
const crypto = require('crypto');

// Console log colors for logging (matching the main server)
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m"
};

// Log process steps with timestamp and formatting
function logStep(step, message) {
  const timestamp = new Date().toISOString();
  console.log(`${colors.cyan}[${timestamp}] ${colors.bright}${colors.yellow}[${step}]${colors.reset} ${message}`);
}

// Log errors with timestamp and formatting
function logError(step, message, error) {
  const timestamp = new Date().toISOString();
  console.error(`${colors.red}[${timestamp}] ${colors.bright}${colors.bgRed}[${step} ERROR]${colors.reset} ${message}`);
  if (error) console.error(error);
}

// Admin password - in a production environment, this should be in environment variables
const ADMIN_PASSWORD = 'FSaX54SB';

// Store active admin tokens with expiration times (4 hours)
const adminTokens = new Map();

// Configure multer for company logo uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads', 'company-logos'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'company-logo-' + uniqueSuffix + ext);
  }
});

// Configure storage for Excel file uploads
const excelStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads', 'excel-imports'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'company-import-' + uniqueSuffix + ext);
  }
});

// Company logo upload middleware
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Excel file upload middleware
const uploadExcel = multer({
  storage: excelStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' || 
        file.mimetype === 'application/vnd.ms-excel') {
      cb(null, true);
    } else {
      cb(new Error('Only Excel files are allowed'));
    }
  }
});

// Middleware to verify admin token
function verifyAdminToken(req, res, next) {
  const token = req.headers['admin-token'];
  
  logStep("ADMIN_AUTH", `Checking admin token: ${!!token}`);
  
  if (token && adminTokens.has(token)) {
    const expiration = adminTokens.get(token);
    
    if (Date.now() < expiration) {
      // Token is valid
      logStep("ADMIN_AUTH", "Admin token verified");
      return next();
    } else {
      // Token expired, remove it
      logStep("ADMIN_AUTH", "Admin token expired");
      adminTokens.delete(token);
    }
  }
  
  logError("ADMIN_AUTH", "Invalid or missing admin token");
  return res.status(401).json({ error: 'Invalid or expired admin token' });
}

// Apply token auth to user routes only (not admin routes)
router.use((req, res, next) => {
  // Skip authentication for admin routes - they will use token verification
  if (req.path.startsWith('/admin/')) {
    return next();
  }
  
  // Apply token authentication for user routes
  authenticateToken(req, res, next);
});

// Generate admin token
router.post('/admin/login', (req, res) => {
  const { adminPassword } = req.body;
  
  logStep("ADMIN_LOGIN", `Admin login attempt, password provided: ${!!adminPassword}`);
  
  if (adminPassword === ADMIN_PASSWORD) {
    // Generate random token
    const token = crypto.randomBytes(32).toString('hex');
    
    // Store token with 4-hour expiration
    const expiration = Date.now() + (4 * 60 * 60 * 1000);
    adminTokens.set(token, expiration);
    
    logStep("ADMIN_LOGIN", `Admin login successful, token generated: ${token.substring(0, 8)}...`);
    
    return res.json({ 
      success: true, 
      token, 
      expiration
    });
  }
  
  logError("ADMIN_LOGIN", "Admin login failed: Invalid password");
  return res.status(403).json({ error: 'Invalid admin password' });
});

// Utility function to validate and truncate URL if needed
function validateCareerPageUrl(url) {
  if (!url) return url;
  
  // Truncate URL if it's too long (for database VARCHAR(500) limit)
  const MAX_URL_LENGTH = 490; // Slightly below 500 to be safe
  
  if (url.length > MAX_URL_LENGTH) {
    logStep("CAREER", `URL too long (${url.length} chars), truncating to ${MAX_URL_LENGTH} chars`);
    return url.substring(0, MAX_URL_LENGTH);
  }
  
  return url;
}

// Initialize Career Pages database tables
async function initCareerDatabase(pool) {
  try {
    const connection = await pool.getConnection();
    logStep("CAREER", "Initializing career pages database tables");

    // Create companies table with TEXT type for career_page_url
    await connection.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        career_page_url TEXT NOT NULL,
        description TEXT,
        industry VARCHAR(100),
        location VARCHAR(100),
        logo_url VARCHAR(500),
        created_by VARCHAR(36),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (industry),
        INDEX (location),
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);
    logStep("CAREER", "Companies table initialized");

    // Check if career_page_url needs to be altered from VARCHAR to TEXT
    try {
      // Try to alter column if it exists as VARCHAR
      await connection.query(`
        ALTER TABLE companies 
        MODIFY COLUMN career_page_url TEXT NOT NULL
      `);
      logStep("CAREER", "Upgraded career_page_url column to TEXT type");
    } catch (err) {
      // If error is not about column already being TEXT, log it
      if (!err.message.includes("Data truncation")) {
        logStep("CAREER", "career_page_url column is already TEXT type or another error occurred");
      }
    }

    // Create user career page visits table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS user_career_page_visits (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        company_id VARCHAR(36) NOT NULL,
        first_visit_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_visit_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        status ENUM('applied', 'not_interested', 'no_jobs_available') NULL,
        status_updated_at TIMESTAMP NULL,
        notes TEXT,
        reminder_sent BOOLEAN DEFAULT FALSE,
        is_saved BOOLEAN DEFAULT FALSE,
        last_reminded_at TIMESTAMP NULL,
        INDEX (user_id),
        INDEX (company_id),
        INDEX (status),
        INDEX (is_saved),
        UNIQUE KEY user_company (user_id, company_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
      )
    `);
    logStep("CAREER", "User career page visits table initialized");

    // Check if is_saved column exists, add it if not
    try {
      await connection.query(`SELECT is_saved FROM user_career_page_visits LIMIT 1`);
      logStep("CAREER", "is_saved column already exists in user_career_page_visits table");
    } catch (err) {
      if (err.message.includes('Unknown column')) {
        await connection.query(`
          ALTER TABLE user_career_page_visits
          ADD COLUMN is_saved BOOLEAN DEFAULT FALSE,
          ADD INDEX (is_saved)
        `);
        logStep("CAREER", "Added is_saved column to user_career_page_visits table");
      } else {
        throw err;
      }
    }

    // Check if last_reminded_at column exists, add it if not
    try {
      await connection.query(`SELECT last_reminded_at FROM user_career_page_visits LIMIT 1`);
      logStep("CAREER", "last_reminded_at column already exists in user_career_page_visits table");
    } catch (err) {
      if (err.message.includes('Unknown column')) {
        await connection.query(`
          ALTER TABLE user_career_page_visits
          ADD COLUMN last_reminded_at TIMESTAMP NULL
        `);
        logStep("CAREER", "Added last_reminded_at column to user_career_page_visits table");
      } else {
        throw err;
      }
    }

    // Add some sample companies if the table is empty
    const [companies] = await connection.query('SELECT COUNT(*) as count FROM companies');
    if (companies[0].count === 0) {
      logStep("CAREER", "Adding sample companies");

      const sampleCompanies = [
        {
          id: uuidv4(),
          name: 'TechCorp Inc.',
          career_page_url: 'https://techcorp.example.com/careers',
          description: 'Leading software development company specializing in cloud solutions and enterprise applications.',
          industry: 'Technology',
          location: 'United States'
        },
        {
          id: uuidv4(),
          name: 'Finance Solutions',
          career_page_url: 'https://financesolve.example.com/jobs',
          description: 'Global financial services firm offering wealth management, investment banking, and financial technology solutions.',
          industry: 'Finance',
          location: 'United States'
        },
        {
          id: uuidv4(),
          name: 'HealthPlus',
          career_page_url: 'https://healthplus.example.com/careers',
          description: 'Healthcare provider focusing on telehealth, wellness programs, and integrated health management systems.',
          industry: 'Healthcare',
          location: 'Remote'
        }
      ];

      for (const company of sampleCompanies) {
        await connection.query(`
          INSERT INTO companies (id, name, career_page_url, description, industry, location) 
          VALUES (?, ?, ?, ?, ?, ?)
        `, [company.id, company.name, company.career_page_url, company.description, company.industry, company.location]);
      }
      logStep("CAREER", `Added ${sampleCompanies.length} sample companies`);
    }

    // Create directories for uploads
    await initCareerAdminFolders();

    connection.release();
    logStep("CAREER", "Career pages database initialization complete");
    return true;
  } catch (error) {
    logError("CAREER", "Failed to initialize career pages database", error);
    throw error;
  }
}

// Create directory for Excel imports and company logos
async function initCareerAdminFolders() {
  try {
    // Create uploads directory for company logos
    await fs.mkdir(path.join(__dirname, 'uploads', 'company-logos'), { recursive: true });
    logStep("CAREER", "Company logos directory created or verified");
    
    // Create uploads directory for Excel imports
    await fs.mkdir(path.join(__dirname, 'uploads', 'excel-imports'), { recursive: true });
    logStep("CAREER", "Excel imports directory created or verified");
  } catch (error) {
    logError("CAREER", "Error creating upload directories", error);
  }
}

// ===== USER API ROUTES =====

// Get paginated list of companies
router.get('/companies', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 9;
    const offset = (page - 1) * limit;
    
    // Get filter parameters
    const searchTerm = req.query.search ? `%${req.query.search}%` : null;
    const industry = req.query.industry || null;
    const location = req.query.location || null;
    const statusFilter = req.query.status || 'fresh'; // Default to fresh
    
    // Build where clause
    let whereClause = '';
    let params = [];
    
    // Start building the where clause
    whereClause = 'WHERE ';
    let hasCondition = false;
    
    if (searchTerm) {
      whereClause += '(c.name LIKE ? OR c.description LIKE ?)';
      params.push(searchTerm, searchTerm);
      hasCondition = true;
    }
    
    if (industry) {
      if (hasCondition) whereClause += ' AND ';
      whereClause += 'c.industry = ?';
      params.push(industry);
      hasCondition = true;
    }
    
    if (location) {
      if (hasCondition) whereClause += ' AND ';
      whereClause += 'c.location = ?';
      params.push(location);
      hasCondition = true;
    }
    
    // Apply status filter if specified
    if (statusFilter && statusFilter !== 'all') {
      if (hasCondition) whereClause += ' AND ';
      
      if (statusFilter === 'fresh') {
        whereClause += 'v.id IS NULL';
      } else if (statusFilter === 'visited') {
        whereClause += 'v.id IS NOT NULL';
      } else if (statusFilter === 'saved') {
        whereClause += 'v.is_saved = TRUE';
      } else {
        whereClause += 'v.status = ?';
        params.push(statusFilter);
      }
      
      hasCondition = true;
    }
    
    // If no conditions were added, remove WHERE
    if (!hasCondition) {
      whereClause = '';
    }
    
    // Query to get companies
    const query = `
      SELECT c.*, 
             v.status, 
             v.is_saved, 
             v.first_visit_date, 
             v.last_visit_date,
             v.notes
      FROM companies c
      LEFT JOIN user_career_page_visits v ON c.id = v.company_id AND v.user_id = ?
      ${whereClause}
      ORDER BY c.created_at DESC
      LIMIT ? OFFSET ?
    `;
    
    // Add user_id and pagination params
    params.unshift(req.user.id);
    params.push(limit, offset);
    
    // Get companies and total count
    const [companies] = await req.db.query(query, params);
    
    // Count total matching companies for pagination
    const countQuery = `
      SELECT COUNT(*) as total
      FROM companies c
      LEFT JOIN user_career_page_visits v ON c.id = v.company_id AND v.user_id = ?
      ${whereClause}
    `;
    
    // Remove pagination params for count query
    const countParams = params.slice(0, params.length - 2);
    
    const [countResult] = await req.db.query(countQuery, countParams);
    const total = countResult[0].total;
    
    // Get list of industries for filters
    const [industries] = await req.db.query(`
      SELECT DISTINCT industry FROM companies WHERE industry IS NOT NULL AND industry != ''
    `);
    
    // Get list of locations for filters
    const [locations] = await req.db.query(`
      SELECT DISTINCT location FROM companies WHERE location IS NOT NULL AND location != ''
    `);
    
    res.json({
      companies,
      industries: industries.map(i => i.industry),
      locations: locations.map(l => l.location),
      hasMore: offset + companies.length < total,
      total
    });
  } catch (error) {
    logError("CAREER", "Error getting companies", error);
    res.status(500).json({ error: 'Failed to get companies' });
  }
});

// Add a new company
router.post('/companies', upload.single('logo'), async (req, res) => {
  try {
    const { name, career_page_url, description, industry, location } = req.body;
    
    // Validate required fields
    if (!name || !career_page_url || !description || !industry || !location) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const id = uuidv4();
    let logoUrl = null;
    
    // Handle logo upload
    if (req.file) {
      if (req.bucket) {
        // Upload to Google Cloud Storage if available
        const filename = req.file.filename;
        const filepath = req.file.path;
        
        const destination = `company-logos/${filename}`;
        
        await req.bucket.upload(filepath, {
          destination: destination,
          metadata: {
            contentType: req.file.mimetype,
          },
        });
        
        // Generate public URL
        logoUrl = `https://storage.googleapis.com/${process.env.GOOGLE_CLOUD_BUCKET_NAME}/${destination}`;
        
        // Delete local file
        await fs.unlink(filepath);
      } else {
        // Use local path if GCS not available
        logoUrl = `/uploads/company-logos/${req.file.filename}`;
      }
    }
    
    // Validate and potentially truncate URL
    const validatedUrl = validateCareerPageUrl(career_page_url);
    
    // Insert company into database
    await req.db.query(`
      INSERT INTO companies (id, name, career_page_url, description, industry, location, logo_url, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, name, validatedUrl, description, industry, location, logoUrl, req.user.id]);
    
    res.json({ 
      success: true, 
      message: 'Company added successfully',
      company: {
        id,
        name,
        career_page_url: validatedUrl,
        description,
        industry,
        location,
        logo_url: logoUrl,
        created_by: req.user.id
      }
    });
  } catch (error) {
    logError("CAREER", "Error adding company", error);
    res.status(500).json({ error: 'Failed to add company' });
  }
});

// Get user's application history
router.get('/applications', async (req, res) => {
  try {
    const query = `
      SELECT v.*, c.name, c.industry, c.location, c.career_page_url, c.logo_url
      FROM user_career_page_visits v
      JOIN companies c ON v.company_id = c.id
      WHERE v.user_id = ?
      ORDER BY v.last_visit_date DESC
    `;
    
    const [visits] = await req.db.query(query, [req.user.id]);
    
    // Format the results to include company info
    const applications = visits.map(visit => ({
      id: visit.id,
      company: {
        id: visit.company_id,
        name: visit.name,
        industry: visit.industry,
        location: visit.location,
        career_page_url: visit.career_page_url,
        logo_url: visit.logo_url
      },
      first_visit_date: visit.first_visit_date,
      last_visit_date: visit.last_visit_date,
      status: visit.status,
      status_updated_at: visit.status_updated_at,
      notes: visit.notes,
      is_saved: visit.is_saved
    }));
    
    res.json({ applications });
  } catch (error) {
    logError("CAREER", "Error getting applications", error);
    res.status(500).json({ error: 'Failed to get applications' });
  }
});

// Track when a user visits a career page
router.post('/track-visit', async (req, res) => {
  try {
    const { companyId } = req.body;
    
    if (!companyId) {
      return res.status(400).json({ error: 'Company ID is required' });
    }
    
    // Check if company exists
    const [companies] = await req.db.query('SELECT id FROM companies WHERE id = ?', [companyId]);
    if (companies.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Check if user has already visited this company
    const [visits] = await req.db.query(
      'SELECT id FROM user_career_page_visits WHERE user_id = ? AND company_id = ?', 
      [req.user.id, companyId]
    );
    
    if (visits.length > 0) {
      // Update last visit date
      await req.db.query(
        'UPDATE user_career_page_visits SET last_visit_date = NOW() WHERE id = ?',
        [visits[0].id]
      );
    } else {
      // Create new visit record
      const visitId = uuidv4();
      await req.db.query(
        'INSERT INTO user_career_page_visits (id, user_id, company_id) VALUES (?, ?, ?)',
        [visitId, req.user.id, companyId]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    logError("CAREER", "Error tracking visit", error);
    res.status(500).json({ error: 'Failed to track visit' });
  }
});

// Check for pending status updates - enhanced for lightbox
router.get('/pending-status', async (req, res) => {
  try {
    // Get time threshold (24 hours ago)
    const oneDayAgo = new Date();
    oneDayAgo.setHours(oneDayAgo.getHours() - 24);
    
    // Get companies visited but without status, not recently reminded
    const query = `
      SELECT v.id as visit_id, c.*
      FROM user_career_page_visits v
      JOIN companies c ON v.company_id = c.id
      WHERE v.user_id = ? 
      AND v.status IS NULL 
      AND (v.last_reminded_at IS NULL OR v.last_reminded_at < ?)
      AND v.last_visit_date < ? 
      ORDER BY v.last_visit_date DESC
      LIMIT 1
    `;
    
    const [pendingVisits] = await req.db.query(
      query, 
      [req.user.id, oneDayAgo.toISOString(), oneDayAgo.toISOString()]
    );
    
    if (pendingVisits.length > 0) {
      // Mark as reminded
      await req.db.query(
        'UPDATE user_career_page_visits SET last_reminded_at = NOW() WHERE id = ?',
        [pendingVisits[0].visit_id]
      );
      
      // Format the company
      const pendingCompany = {
        id: pendingVisits[0].id,
        name: pendingVisits[0].name,
        industry: pendingVisits[0].industry,
        location: pendingVisits[0].location,
        career_page_url: pendingVisits[0].career_page_url,
        logo_url: pendingVisits[0].logo_url,
        description: pendingVisits[0].description,
        visit_id: pendingVisits[0].visit_id
      };
      
      res.json({ 
        hasPending: true,
        pendingCompany
      });
    } else {
      res.json({ 
        hasPending: false 
      });
    }
  } catch (error) {
    logError("CAREER", "Error checking pending status", error);
    res.status(500).json({ error: 'Failed to check pending status' });
  }
});

// Get status summary (for analytics)
router.get('/analytics', async (req, res) => {
  try {
    // Get status breakdown
    const statusQuery = `
      SELECT 
        COALESCE(status, 'pending') as status,
        COUNT(*) as count
      FROM user_career_page_visits
      WHERE user_id = ?
      GROUP BY status
    `;
    
    const [statusBreakdown] = await req.db.query(statusQuery, [req.user.id]);
    
    // Get industry breakdown
    const industryQuery = `
      SELECT 
        c.industry,
        COUNT(*) as count
      FROM user_career_page_visits v
      JOIN companies c ON v.company_id = c.id
      WHERE v.user_id = ?
      GROUP BY c.industry
      ORDER BY count DESC
    `;
    
    const [industryBreakdown] = await req.db.query(industryQuery, [req.user.id]);
    
    // Get weekly activity
    const weeklyQuery = `
      SELECT COUNT(*) as count
      FROM user_career_page_visits
      WHERE user_id = ? AND last_visit_date > DATE_SUB(NOW(), INTERVAL 7 DAY)
    `;
    
    const [weeklyResult] = await req.db.query(weeklyQuery, [req.user.id]);
    
    // Get total applications
    const totalQuery = `
      SELECT COUNT(*) as count
      FROM user_career_page_visits
      WHERE user_id = ? AND status = 'applied'
    `;
    
    const [totalResult] = await req.db.query(totalQuery, [req.user.id]);
    
    // Get timeline data (last 30 days)
    const timelineQuery = `
      SELECT 
        DATE(last_visit_date) as date,
        COUNT(*) as count
      FROM user_career_page_visits
      WHERE user_id = ? AND last_visit_date > DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(last_visit_date)
      ORDER BY date
    `;
    
    const [timelineData] = await req.db.query(timelineQuery, [req.user.id]);
    
    res.json({
      analytics: {
        statusBreakdown,
        industryBreakdown,
        weeklyActivity: weeklyResult[0].count,
        totalApplications: totalResult[0].count,
        timelineData
      }
    });
  } catch (error) {
    logError("CAREER", "Error getting analytics", error);
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

// Update application status
router.post('/update-status', async (req, res) => {
  try {
    const { companyId, status, notes } = req.body;
    
    if (!companyId || !status) {
      return res.status(400).json({ error: 'Company ID and status are required' });
    }
    
    // Validate status
    const validStatuses = ['applied', 'not_interested', 'no_jobs_available'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    // Check if visit record exists
    const [visits] = await req.db.query(
      'SELECT id FROM user_career_page_visits WHERE user_id = ? AND company_id = ?',
      [req.user.id, companyId]
    );
    
    if (visits.length === 0) {
      // Create new visit record with status
      const visitId = uuidv4();
      await req.db.query(
        'INSERT INTO user_career_page_visits (id, user_id, company_id, status, status_updated_at, notes) VALUES (?, ?, ?, ?, NOW(), ?)',
        [visitId, req.user.id, companyId, status, notes || null]
      );
    } else {
      // Update existing record
      await req.db.query(
        'UPDATE user_career_page_visits SET status = ?, status_updated_at = NOW(), notes = ? WHERE id = ?',
        [status, notes || null, visits[0].id]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    logError("CAREER", "Error updating application status", error);
    res.status(500).json({ error: 'Failed to update application status' });
  }
});

// Update application notes
router.post('/update-notes', async (req, res) => {
  try {
    const { companyId, notes } = req.body;
    
    if (!companyId) {
      return res.status(400).json({ error: 'Company ID is required' });
    }
    
    // Check if visit record exists
    const [visits] = await req.db.query(
      'SELECT id FROM user_career_page_visits WHERE user_id = ? AND company_id = ?',
      [req.user.id, companyId]
    );
    
    if (visits.length === 0) {
      // Create new visit record with notes
      const visitId = uuidv4();
      await req.db.query(
        'INSERT INTO user_career_page_visits (id, user_id, company_id, notes) VALUES (?, ?, ?, ?)',
        [visitId, req.user.id, companyId, notes || null]
      );
    } else {
      // Update existing record
      await req.db.query(
        'UPDATE user_career_page_visits SET notes = ? WHERE id = ?',
        [notes || null, visits[0].id]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    logError("CAREER", "Error updating notes", error);
    res.status(500).json({ error: 'Failed to update notes' });
  }
});

// Toggle save status for a company
router.post('/toggle-save', async (req, res) => {
  try {
    const { companyId } = req.body;
    
    if (!companyId) {
      return res.status(400).json({ error: 'Company ID is required' });
    }
    
    // Check if company exists
    const [companies] = await req.db.query('SELECT id FROM companies WHERE id = ?', [companyId]);
    if (companies.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Check if visit record exists
    const [visits] = await req.db.query(
      'SELECT id, is_saved FROM user_career_page_visits WHERE user_id = ? AND company_id = ?',
      [req.user.id, companyId]
    );
    
    let isSaved = false;
    
    if (visits.length === 0) {
      // Create new visit record with saved flag
      const visitId = uuidv4();
      await req.db.query(
        'INSERT INTO user_career_page_visits (id, user_id, company_id, is_saved) VALUES (?, ?, ?, TRUE)',
        [visitId, req.user.id, companyId]
      );
      isSaved = true;
    } else {
      // Toggle saved status
      isSaved = !visits[0].is_saved;
      await req.db.query(
        'UPDATE user_career_page_visits SET is_saved = ? WHERE id = ?',
        [isSaved, visits[0].id]
      );
    }
    
    res.json({ 
      success: true,
      isSaved
    });
  } catch (error) {
    logError("CAREER", "Error toggling save status", error);
    res.status(500).json({ error: 'Failed to toggle save status' });
  }
});

// Get saved companies
router.get('/saved', async (req, res) => {
  try {
    const query = `
      SELECT c.*, v.status, v.notes, v.is_saved, v.first_visit_date, v.last_visit_date
      FROM companies c
      JOIN user_career_page_visits v ON c.id = v.company_id 
      WHERE v.user_id = ? AND v.is_saved = TRUE
      ORDER BY v.last_visit_date DESC
    `;
    
    const [companies] = await req.db.query(query, [req.user.id]);
    
    res.json({ savedCompanies: companies });
  } catch (error) {
    logError("CAREER", "Error getting saved companies", error);
    res.status(500).json({ error: 'Failed to get saved companies' });
  }
});

// ===== ADMIN API ENDPOINTS =====

// Get all companies with pagination (admin version)
router.post('/admin/companies', verifyAdminToken, async (req, res) => {
  try {
    const page = parseInt(req.body.page) || 1;
    const limit = parseInt(req.body.limit) || 20;
    const offset = (page - 1) * limit;
    
    // Get filter parameters
    const searchTerm = req.body.search ? `%${req.body.search}%` : null;
    
    // Build where clause
    let whereClause = '';
    let params = [];
    
    if (searchTerm) {
      whereClause = 'WHERE (name LIKE ? OR description LIKE ? OR industry LIKE ? OR location LIKE ?)';
      params.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }
    
    // Query to get companies
    const query = `
      SELECT * FROM companies
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `;
    
    // Add pagination params
    params.push(limit, offset);
    
    // Get companies
    const [companies] = await req.db.query(query, params);
    
    // Count total matching companies for pagination
    const countQuery = `
      SELECT COUNT(*) as total
      FROM companies
      ${whereClause}
    `;
    
    const [countResult] = await req.db.query(countQuery, params.slice(0, params.length - 2));
    const total = countResult[0].total;
    
    logStep("ADMIN", `Found ${companies.length} companies, total: ${total}`);
    
    res.json({
      companies,
      hasMore: offset + companies.length < total,
      total
    });
  } catch (error) {
    logError("CAREER", "Error getting companies for admin", error);
    res.status(500).json({ error: 'Failed to get companies' });
  }
});

// Import companies from Excel file
router.post('/admin/import', verifyAdminToken, uploadExcel.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    logStep("ADMIN", "Processing Excel import");
    
    // Read Excel file
    const workbook = XLSX.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    
    // Convert to JSON
    const companies = XLSX.utils.sheet_to_json(worksheet);
    
    if (companies.length === 0) {
      return res.status(400).json({ error: 'No data found in the Excel file' });
    }
    
    // Process and validate companies
    const validCompanies = [];
    const invalidCompanies = [];
    
    for (const company of companies) {
      // Check required fields
      if (!company.Name || !company['Career Page URL']) {
        invalidCompanies.push(company);
        continue;
      }
      
      // Validate/truncate the URL
      const validatedUrl = validateCareerPageUrl(company['Career Page URL']);
      
      // Format the company data
      validCompanies.push({
        id: uuidv4(),
        name: company.Name,
        career_page_url: validatedUrl,
        description: company.Description || '',
        industry: company.Industry || '',
        location: company.Location || '',
        created_at: new Date(),
        updated_at: new Date()
      });
    }
    
    // Insert valid companies into database
    if (validCompanies.length > 0) {
      const connection = await req.db.getConnection();
      try {
        await connection.beginTransaction();
        
        for (const company of validCompanies) {
          await connection.query(`
            INSERT INTO companies (id, name, career_page_url, description, industry, location, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `, [
            company.id,
            company.name,
            company.career_page_url,
            company.description,
            company.industry,
            company.location,
            company.created_at,
            company.updated_at
          ]);
        }
        
        await connection.commit();
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    }
    
    // Delete the uploaded file
    await fs.unlink(req.file.path);
    
    logStep("ADMIN", `Import completed: ${validCompanies.length} valid, ${invalidCompanies.length} invalid`);
    
    res.json({
      success: true,
      imported: validCompanies.length,
      invalid: invalidCompanies.length,
      message: `Successfully imported ${validCompanies.length} companies. ${invalidCompanies.length} companies were invalid.`
    });
  } catch (error) {
    logError("CAREER", "Error importing companies", error);
    
    // Try to delete the file if it exists
    if (req.file && req.file.path) {
      try {
        await fs.unlink(req.file.path);
      } catch (unlinkError) {
        logError("CAREER", "Error deleting uploaded file", unlinkError);
      }
    }
    
    res.status(500).json({ error: 'Failed to import companies' });
  }
});

// Get user statistics for admin
router.get('/admin/stats', verifyAdminToken, async (req, res) => {
  try {
    // Get overall stats
    const statsQuery = `
      SELECT 
        COUNT(DISTINCT v.user_id) as active_users,
        COUNT(DISTINCT v.company_id) as visited_companies,
        SUM(CASE WHEN v.status = 'applied' THEN 1 ELSE 0 END) as total_applications,
        AVG(CASE WHEN v.status = 'applied' THEN 1 ELSE 0 END) as application_rate
      FROM user_career_page_visits v
    `;
    
    const [statsResults] = await req.db.query(statsQuery);
    
    // Get top industries
    const industriesQuery = `
      SELECT 
        c.industry,
        COUNT(*) as count
      FROM user_career_page_visits v
      JOIN companies c ON v.company_id = c.id
      WHERE v.status = 'applied'
      GROUP BY c.industry
      ORDER BY count DESC
      LIMIT 5
    `;
    
    const [topIndustries] = await req.db.query(industriesQuery);
    
    res.json({
      stats: statsResults[0],
      topIndustries
    });
  } catch (error) {
    logError("CAREER", "Error getting admin stats", error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Export router and init function
module.exports = {
  router,
  initCareerDatabase
};
