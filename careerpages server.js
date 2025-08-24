// careerpages.js - Career pages management module

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { authenticateToken } = require('./auth');

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

// Apply middleware to all routes
router.use(authenticateToken);

// Initialize Career Pages database tables
async function initCareerDatabase(pool) {
  try {
    const connection = await pool.getConnection();
    logStep("CAREER", "Initializing career pages database tables");

    // Create companies table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        career_page_url VARCHAR(500) NOT NULL,
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
        INDEX (user_id),
        INDEX (company_id),
        INDEX (status),
        UNIQUE KEY user_company (user_id, company_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
      )
    `);
    logStep("CAREER", "User career page visits table initialized");

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

    connection.release();
    logStep("CAREER", "Career pages database initialization complete");
    return true;
  } catch (error) {
    logError("CAREER", "Failed to initialize career pages database", error);
    throw error;
  }
}

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

// ===== API Routes =====

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
    
    // Build where clause
    let whereClause = '';
    let params = [];
    
    if (searchTerm || industry || location) {
      whereClause = 'WHERE ';
      
      if (searchTerm) {
        whereClause += '(name LIKE ? OR description LIKE ?)';
        params.push(searchTerm, searchTerm);
      }
      
      if (industry) {
        if (params.length > 0) whereClause += ' AND ';
        whereClause += 'industry = ?';
        params.push(industry);
      }
      
      if (location) {
        if (params.length > 0) whereClause += ' AND ';
        whereClause += 'location = ?';
        params.push(location);
      }
    }
    
    // Query to get companies
    const query = `
      SELECT c.*, v.status
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
      FROM companies
      ${whereClause}
    `;
    
    // Remove user_id and pagination params for count query
    const countParams = params.slice(1, params.length - 2);
    
    const [countResult] = await req.db.query(countQuery, countParams);
    const total = countResult[0].total;
    
    res.json({
      companies,
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
    
    // Insert company into database
    await req.db.query(`
      INSERT INTO companies (id, name, career_page_url, description, industry, location, logo_url, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, name, career_page_url, description, industry, location, logoUrl, req.user.id]);
    
    res.json({ 
      success: true, 
      message: 'Company added successfully',
      company: {
        id,
        name,
        career_page_url,
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
      notes: visit.notes
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
        'UPDATE user_career_page_visits SET last_visit_date = NOW(), reminder_sent = FALSE WHERE id = ?',
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

// Check for pending status updates
router.get('/pending-status', async (req, res) => {
  try {
    // Get companies visited but without status, not reminded yet
    const query = `
      SELECT v.id as visit_id, c.*
      FROM user_career_page_visits v
      JOIN companies c ON v.company_id = c.id
      WHERE v.user_id = ? 
      AND v.status IS NULL 
      AND v.reminder_sent = FALSE
      ORDER BY v.last_visit_date DESC
      LIMIT 5
    `;
    
    const [pendingVisits] = await req.db.query(query, [req.user.id]);
    
    if (pendingVisits.length > 0) {
      // Mark as reminded
      await req.db.query(
        'UPDATE user_career_page_visits SET reminder_sent = TRUE WHERE id = ?',
        [pendingVisits[0].visit_id]
      );
      
      // Format the companies
      const pendingCompanies = pendingVisits.map(visit => ({
        id: visit.id,
        name: visit.name,
        industry: visit.industry,
        location: visit.location,
        career_page_url: visit.career_page_url,
        logo_url: visit.logo_url,
        description: visit.description
      }));
      
      res.json({ pendingCompanies });
    } else {
      res.json({ pendingCompanies: [] });
    }
  } catch (error) {
    logError("CAREER", "Error checking pending status", error);
    res.status(500).json({ error: 'Failed to check pending status' });
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

// Export the router and initialization function
module.exports = {
  router,
  initCareerDatabase
};
