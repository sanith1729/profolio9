// profolioserver.js - Main server file that integrates all modules

// This must be the very first line to ensure environment variables are loaded
require('dotenv').config({ path: process.env.NODE_ENV === 'production' ? '/root/profolio/.env' : './.env' });

// Debug environment variables
console.log('==== ENVIRONMENT VARIABLES DEBUG ====');
console.log('GOOGLE_CLOUD_BUCKET_NAME:', process.env.GOOGLE_CLOUD_BUCKET_NAME || 'NOT SET');
console.log('GOOGLE_CLOUD_KEY_PATH:', process.env.GOOGLE_CLOUD_KEY_PATH || 'NOT SET');
console.log('GOOGLE_CLOUD_PROJECT_ID:', process.env.GOOGLE_CLOUD_PROJECT_ID || 'NOT SET');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'SET (value hidden)' : 'NOT SET');
console.log('OPENAI_API_KEY:', process.env.OPENAI_API_KEY ? 'SET (value hidden)' : 'NOT SET');
console.log('====================================');

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const fs = require('fs').promises;
const multer = require('multer');
const jwt = require('jsonwebtoken');
const puppeteer = require('puppeteer'); // Added for PDF generation

// Import modules
const { router: authRouter, authenticateToken } = require('./auth');
const profolioModule = require('./profolio'); // Your profolio generation module
const editorModule = require('./editormode'); // Editor module
const adminModule = require('./userManagement'); // User management module
const { getStorage, getBucket } = require('./imageUpload'); // Image upload utilities
const databaseRouter = require('./database'); // Database dashboard module
const { router: resumeRouter, initResumeDatabase } = require('./resumeChanger'); // Resume changer module

// Initialize Express app
const app = express();

// Console log colors for logging
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

// Log success with formatting
function logSuccess(step, message) {
  const timestamp = new Date().toISOString();
  console.log(`${colors.green}[${timestamp}] ${colors.bright}${colors.bgGreen}[${step} SUCCESS]${colors.reset} ${message}`);
}

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Configure multer for temporary storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit for resume files
  }
});

// Make upload middleware available to routes
app.locals.upload = upload;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));  // Serve frontend from public folder
app.use('/portfolios', express.static(path.join(__dirname, 'portfolios')));  // Serve generated portfolios
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));  // Serve uploaded images

// Validate required environment variables
const requiredEnvVars = [
  'GOOGLE_CLOUD_KEY_PATH',
  'GOOGLE_CLOUD_BUCKET_NAME',
  'GOOGLE_CLOUD_PROJECT_ID',
  'OPENAI_API_KEY',
  'JWT_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('\x1b[31m%s\x1b[0m', '=== STARTUP ERROR: MISSING ENVIRONMENT VARIABLES ===');
  console.error('The following required environment variables are missing:');
  missingEnvVars.forEach(varName => {
    console.error(`- ${varName}`);
  });
  console.error('\x1b[31m%s\x1b[0m', '=== Please update your .env file and restart the server ===');
  process.exit(1); // Exit with error code
}

// Create database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'superadmin',
  password: process.env.DB_PASSWORD || 'SuperSecure!Pass123',
  database: process.env.DB_NAME || 'profolio',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Make db available to routes
app.use((req, res, next) => {
  req.db = pool;
  
  // Also make Google Cloud Storage bucket available
  try {
    req.bucket = getBucket();
  } catch (error) {
    logError("SERVER", "Failed to get Google Cloud Storage bucket", error);
  }
  
  next();
});

// Initialize Google Cloud Storage
try {
  logStep("SERVER", `Initializing Google Cloud Storage with bucket: ${process.env.GOOGLE_CLOUD_BUCKET_NAME}`);
  
  // This will initialize the storage and bucket instances via the getStorage() function
  getStorage();
  
  logSuccess("SERVER", "Google Cloud Storage initialized successfully");
} catch (error) {
  logError("SERVER", "Failed to initialize Google Cloud Storage", error);
}

// Routes
app.use('/api/auth', authRouter);

// Use the profolio module
if (profolioModule && profolioModule.router) {
  app.use('/api/profolio', profolioModule.router);
  
  // If the module has a template router, use it too
  if (profolioModule.templateRouter) {
    app.use('/api/profolio', profolioModule.templateRouter);
  }
  
  logStep("SERVER", "Profolio module routes mounted");
} else {
  logError("SERVER", "Profolio module not found or doesn't export a router");
}

// Use the editor module
app.use('/', editorModule);
logStep("SERVER", "Editor module routes mounted");

// Mount admin and user management routes
app.use('/api/admin', adminModule);
logStep("SERVER", "Admin module routes mounted");

// Mount the database dashboard router
app.use('/api/database', databaseRouter);
logStep("SERVER", "Database dashboard module routes mounted");

// Mount the resume changer router
app.use('/api/resume', resumeRouter);
logStep("SERVER", "Resume changer module routes mounted");

// Serve database dashboard
app.get('/database-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'database-dashboard.html'));
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Serve resume changer page
app.get('/resume-changer.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'resume-changer.html'));
});

// Add server health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    features: {
      portfolio_generation: true,
      resume_changer: true,
      admin_dashboard: true,
      database_dashboard: true,
      google_cloud_storage: !!process.env.GOOGLE_CLOUD_BUCKET_NAME,
      openai_integration: !!process.env.OPENAI_API_KEY,
      pdf_generation: true
    }
  });
});

// Create required directories if they don't exist
async function initFolders() {
  try {
    // Create portfolios directory
    await fs.mkdir(path.join(__dirname, 'portfolios'), { recursive: true });
    logStep("SERVER", "Portfolios directory created or verified");
    
    // Create uploads directory for local image storage
    await fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true });
    logStep("SERVER", "Uploads directory created or verified");
    
    // Create uploads/profile-images directory
    await fs.mkdir(path.join(__dirname, 'uploads', 'profile-images'), { recursive: true });
    logStep("SERVER", "Profile images directory created or verified");
    
    // Create uploads/project-images directory
    await fs.mkdir(path.join(__dirname, 'uploads', 'project-images'), { recursive: true });
    logStep("SERVER", "Project images directory created or verified");
    
    // Create uploads/editor-images directory
    await fs.mkdir(path.join(__dirname, 'uploads', 'editor-images'), { recursive: true });
    logStep("SERVER", "Editor images directory created or verified");
    
    // Create uploads/template-thumbnails directory
    await fs.mkdir(path.join(__dirname, 'uploads', 'template-thumbnails'), { recursive: true });
    logStep("SERVER", "Template thumbnails directory created or verified");
    
    // Create uploads/resumes directory for temporary resume storage
    await fs.mkdir(path.join(__dirname, 'uploads', 'resumes'), { recursive: true });
    logStep("SERVER", "Resume uploads directory created or verified");
    
    // Also ensure public directory exists
    await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
    logStep("SERVER", "Public directory created or verified");
    
    logSuccess("SERVER", "All required directories initialized");
  } catch (error) {
    logError("SERVER", "Error creating directories", error);
    throw error;
  }
}

// Initialize database
async function initDb() {
  try {
    // Test database connection
    const connection = await pool.getConnection();
    logStep("SERVER", "Connected to MySQL database");
    
    // Create users table if it doesn't exist with all required columns
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        userprofoliolink VARCHAR(500),
        profile_image_url VARCHAR(500),
        template_id VARCHAR(36),
        placeholders JSON,
        role ENUM('admin', 'user') DEFAULT 'user',
        resume_text LONGTEXT,
        resume_filename VARCHAR(255),
        index_html LONGTEXT,
        about_html LONGTEXT,
        projects_html LONGTEXT,
        contact_html LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Check if role column exists, add it if not
    try {
      await connection.query(`SELECT role FROM users LIMIT 1`);
      logStep("SERVER", "Role column already exists in users table");
    } catch (err) {
      if (err.message.includes('Unknown column')) {
        await connection.query(`
          ALTER TABLE users
          ADD COLUMN role ENUM('admin', 'user') DEFAULT 'user' AFTER placeholders
        `);
        logStep("SERVER", "Added role column to users table");
      } else {
        throw err;
      }
    }

    // Check if placeholders column exists, add it if not
    try {
      await connection.query(`SELECT placeholders FROM users LIMIT 1`);
      logStep("SERVER", "Placeholders column already exists in users table");
    } catch (err) {
      if (err.message.includes('Unknown column')) {
        await connection.query(`
          ALTER TABLE users
          ADD COLUMN placeholders JSON AFTER template_id
        `);
        logStep("SERVER", "Added placeholders column to users table");
      } else {
        throw err;
      }
    }

    // Check if resume columns exist, add them if not
    try {
      await connection.query(`SELECT resume_text, resume_filename FROM users LIMIT 1`);
      logStep("SERVER", "Resume columns already exist in users table");
    } catch (err) {
      if (err.message.includes('Unknown column')) {
        await connection.query(`
          ALTER TABLE users
          ADD COLUMN resume_text LONGTEXT,
          ADD COLUMN resume_filename VARCHAR(255)
        `);
        logStep("SERVER", "Added resume columns to users table");
      } else {
        throw err;
      }
    }
    
    // Create userdatajobpending table if it doesn't exist
    await connection.query(`
      CREATE TABLE IF NOT EXISTS userdatajobpending (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        resume_data TEXT NOT NULL,
        state VARCHAR(20) NOT NULL DEFAULT 'queued',
        folder_name VARCHAR(255) NOT NULL,
        folder_path VARCHAR(500) NOT NULL,
        index_state VARCHAR(20) NOT NULL DEFAULT 'queued',
        about_state VARCHAR(20) NOT NULL DEFAULT 'queued',
        projects_state VARCHAR(20) NOT NULL DEFAULT 'queued',
        contact_state VARCHAR(20) NOT NULL DEFAULT 'queued',
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (user_id),
        INDEX (state),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    // Create portfolio_templates table if it doesn't exist
    await connection.query(`
      CREATE TABLE IF NOT EXISTS portfolio_templates (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        thumbnail_url VARCHAR(500),
        category VARCHAR(100),
        index_html LONGTEXT,
        about_html LONGTEXT,
        projects_html LONGTEXT,
        contact_html LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    // Create images table for tracking uploaded images
    await connection.query(`
      CREATE TABLE IF NOT EXISTS images (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        image_type ENUM('profile', 'project', 'portfolio', 'other') NOT NULL,
        image_path VARCHAR(500) NOT NULL,
        image_url VARCHAR(500) NOT NULL,
        project_id VARCHAR(36),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (user_id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Create tailored_resumes table for resume changer functionality (simplified structure)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS tailored_resumes (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        original_filename VARCHAR(255),
        job_requirements TEXT NOT NULL,
        tailored_content LONGTEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (user_id),
        INDEX (created_at),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    logSuccess("SERVER", "Database tables initialized");
    
    connection.release();
  } catch (error) {
    logError("SERVER", "Database initialization error", error);
    logError("SERVER", "Check your database credentials and make sure MySQL is running");
    throw error;
  }
}

// Copy admin dashboard HTML to public folder
async function setupAdminDashboard() {
  try {
    // Ensure public directory exists
    await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
    
    // Copy admin dashboard HTML
    const adminDashboardPath = path.join(__dirname, 'admin-dashboard.html');
    const publicDestPath = path.join(__dirname, 'public', 'admin-dashboard.html');
    
    // Check if admin dashboard exists in root directory
    try {
      await fs.access(adminDashboardPath);
      // If it exists, copy it to public folder
      await fs.copyFile(adminDashboardPath, publicDestPath);
      logSuccess("SERVER", "Admin dashboard copied to public folder");
    } catch (error) {
      // If it doesn't exist, create a simple redirect page
      logStep("SERVER", "Admin dashboard not found, creating placeholder");
      const redirectHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Admin Dashboard</title>
          <meta http-equiv="refresh" content="0;url=/admin">
        </head>
        <body>
          <p>Redirecting to admin dashboard...</p>
        </body>
        </html>
      `;
      await fs.writeFile(publicDestPath, redirectHtml);
      logStep("SERVER", "Created admin dashboard placeholder");
    }
  } catch (error) {
    logError("SERVER", "Error setting up admin dashboard", error);
    // Continue startup even if admin dashboard setup fails
  }
}

// Copy database dashboard HTML to public folder
async function setupDatabaseDashboard() {
  try {
    // Ensure public directory exists
    await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
    
    // Copy database dashboard HTML or create placeholder
    const databaseDashboardPath = path.join(__dirname, 'database-dashboard.html');
    const publicDestPath = path.join(__dirname, 'public', 'database-dashboard.html');
    
    // Check if database dashboard exists in root directory
    try {
      await fs.access(databaseDashboardPath);
      // If it exists, copy it to public folder
      await fs.copyFile(databaseDashboardPath, publicDestPath);
      logSuccess("SERVER", "Database dashboard copied to public folder");
    } catch (error) {
      // If it doesn't exist, create a simple placeholder
      logStep("SERVER", "Database dashboard not found, creating placeholder");
      const placeholderHtml = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Database Dashboard - buildfree.io</title>
          <script src="https://cdn.tailwindcss.com"></script>
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
          <script>
            document.addEventListener('DOMContentLoaded', function() {
              fetch('/api/database/user-data')
                .then(response => {
                  if (!response.ok) {
                    throw new Error('Please log in to access the database dashboard');
                  }
                  return response.json();
                })
                .then(data => {
                  document.getElementById('loading').style.display = 'none';
                  document.getElementById('content').style.display = 'block';
                })
                .catch(error => {
                  document.getElementById('loading').style.display = 'none';
                  document.getElementById('error').textContent = error.message;
                  document.getElementById('error-container').style.display = 'block';
                });
            });
          </script>
        </head>
        <body class="bg-gray-50 min-h-screen">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <h1 class="text-3xl font-bold text-gray-900 mb-8">Database Dashboard</h1>
            
            <div id="loading" class="bg-white p-8 rounded-xl shadow-md text-center">
              <div class="inline-block animate-spin rounded-full h-12 w-12 border-t-4 border-b-4 border-primary-600 mb-4"></div>
              <p class="text-lg text-gray-700">Loading database information...</p>
            </div>
            
            <div id="error-container" class="bg-red-50 border-l-4 border-red-500 p-6 rounded-md mb-8" style="display:none">
              <div class="flex items-center">
                <div class="flex-shrink-0">
                  <i class="fas fa-exclamation-circle text-red-600 text-xl"></i>
                </div>
                <div class="ml-3">
                  <h3 class="text-lg font-medium text-red-800">Error</h3>
                  <p class="text-red-700 mt-1" id="error"></p>
                </div>
              </div>
            </div>
            
            <div id="content" style="display:none">
              <p class="mb-4 text-gray-600">Database dashboard placeholder.</p>
            </div>
          </div>
        </body>
        </html>
      `;
      await fs.writeFile(publicDestPath, placeholderHtml);
      logStep("SERVER", "Created database dashboard placeholder");
    }
  } catch (error) {
    logError("SERVER", "Error setting up database dashboard", error);
    // Continue startup even if database dashboard setup fails
  }
}

// Setup resume changer HTML
async function setupResumeChanger() {
  try {
    // Ensure public directory exists
    await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
    
    const resumeChangerPath = path.join(__dirname, 'resume-changer.html');
    const publicDestPath = path.join(__dirname, 'public', 'resume-changer.html');
    
    // Check if resume changer exists in root directory
    try {
      await fs.access(resumeChangerPath);
      // If it exists, copy it to public folder
      await fs.copyFile(resumeChangerPath, publicDestPath);
      logSuccess("SERVER", "Resume changer copied to public folder");
    } catch (error) {
      logStep("SERVER", "Resume changer HTML not found in root, expecting it in public folder");
    }
  } catch (error) {
    logError("SERVER", "Error setting up resume changer", error);
    // Continue startup even if resume changer setup fails
  }
}

// Catch-all route to serve the frontend for any unmatched routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 3636;
async function startServer() {
  try {
    // Initialize directories
    await initFolders();
    
    // Initialize database
    await initDb();
    
    // Setup admin dashboard
    await setupAdminDashboard();
    
    // Setup database dashboard
    await setupDatabaseDashboard();
    
    // Setup resume changer
    await setupResumeChanger();
    
    // Start the portfolio job processor if it exists
    if (profolioModule && typeof profolioModule.initProcessor === 'function') {
      profolioModule.initProcessor(pool);
      logStep("SERVER", "Portfolio job processor started");
    }
    
    // Start the server
    app.listen(PORT, () => {
      logSuccess("SERVER", `Server running on port ${PORT}`);
      console.log(`\n${colors.bright}${colors.green}=== SERVER STARTED SUCCESSFULLY ===${colors.reset}`);
      console.log(`${colors.cyan}Frontend URL:         ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}`);
      console.log(`${colors.cyan}Admin Dashboard:      ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/admin`);
      console.log(`${colors.cyan}Database Dashboard:   ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/database-dashboard.html`);
      console.log(`${colors.cyan}Resume Changer:       ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/resume-changer.html`);
      console.log(`${colors.cyan}API Endpoints:        ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/api`);
      console.log(`${colors.cyan}Editor URL:           ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/edit-portfolio/{userId}/{page}?token={JWT}`);
      console.log(`${colors.cyan}Health Check:         ${colors.reset}http://${process.env.SERVER_IP || 'localhost'}:${PORT}/api/health`);
      console.log(`${colors.bright}${colors.green}=========================================${colors.reset}\n`);
    });
  } catch (error) {
    logError("SERVER", "Failed to start server", error);
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logError("UNCAUGHT", "Uncaught Exception", error);
  // Keep the process running unless it's a critical error
});

process.on('unhandledRejection', (reason, promise) => {
  logError("UNHANDLED", "Unhandled Rejection", reason);
  // Keep the process running unless it's a critical error
});

// Check if this file is being run directly
if (require.main === module) {
  // Start the application
  startServer().catch(err => {
    logError("STARTUP", "Fatal error during startup", err);
    process.exit(1);
  });
}

// Export the app for testing
module.exports = app;
