// emailIntegration.js - Email integration module for tracking job applications

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { google } = require('googleapis');
const gmail = google.gmail('v1');
const ImapClient = require('emailjs-imap-client');
const simpleParser = require('mailparser').simpleParser;
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
const { authenticateToken } = require('./auth');
const fs = require('fs').promises;
const path = require('path');

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

// Log success with formatting
function logSuccess(step, message) {
  const timestamp = new Date().toISOString();
  console.log(`${colors.green}[${timestamp}] ${colors.bright}${colors.bgGreen}[${step} SUCCESS]${colors.reset} ${message}`);
}

// Apply token auth to user routes only (not admin routes)
router.use((req, res, next) => {
  // Skip authentication for admin routes
  if (req.path.startsWith('/admin/')) {
    return next();
  }
  
  // Apply token authentication for user routes
  authenticateToken(req, res, next);
});

// OAuth configuration for different providers
const oauthProviders = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3636/api/email/auth/google/callback',
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/userinfo.email'
    ]
  },
  outlook: {
    clientId: process.env.OUTLOOK_CLIENT_ID,
    clientSecret: process.env.OUTLOOK_CLIENT_SECRET,
    redirectUri: process.env.OUTLOOK_REDIRECT_URI || 'http://localhost:3636/api/email/auth/outlook/callback',
    scope: [
      'offline_access',
      'Mail.Read',
      'User.Read'
    ]
  }
};

// Encryption utilities for token storage
const encryption = {
  encrypt: (text) => {
    if (!text) return null;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      'aes-256-cbc', 
      Buffer.from(process.env.ENCRYPTION_KEY || 'fallback-encryption-key-32-chars!'), 
      iv
    );
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  },
  
  decrypt: (text) => {
    if (!text) return null;
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc', 
      Buffer.from(process.env.ENCRYPTION_KEY || 'fallback-encryption-key-32-chars!'), 
      iv
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
};

// Initialize email integration database tables
async function initEmailDatabase(pool) {
  try {
    const connection = await pool.getConnection();
    logStep("EMAIL", "Initializing email integration database tables");

    // Create user_email_integrations table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS user_email_integrations (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        email_address VARCHAR(255) NOT NULL,
        provider VARCHAR(50) NOT NULL,
        auth_token TEXT,
        refresh_token TEXT,
        token_expiry TIMESTAMP,
        integration_status ENUM('active', 'expired', 'revoked', 'error') DEFAULT 'active',
        last_sync_time TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (user_id),
        INDEX (email_address),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY user_email (user_id, email_address)
      );
    `);
    logStep("EMAIL", "user_email_integrations table initialized");

    // Create company_emails table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS company_emails (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        company_id VARCHAR(36) NOT NULL, 
        email_id VARCHAR(255) NOT NULL,
        subject TEXT,
        sender VARCHAR(255),
        received_date TIMESTAMP,
        content TEXT,
        is_read BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (company_id) REFERENCES companies(id)
      );
    `);
    logStep("EMAIL", "company_emails table initialized");

    // Create email_threads table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_threads (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        company_id VARCHAR(36) NOT NULL,
        thread_subject TEXT,
        last_update TIMESTAMP,
        message_count INT DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (company_id) REFERENCES companies(id)
      );
    `);
    logStep("EMAIL", "email_threads table initialized");

    // Create email_attachments table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_attachments (
        id VARCHAR(36) PRIMARY KEY,
        email_id VARCHAR(36) NOT NULL,
        filename VARCHAR(255) NOT NULL,
        content_type VARCHAR(100),
        size INT,
        storage_path VARCHAR(500),
        FOREIGN KEY (email_id) REFERENCES company_emails(id) ON DELETE CASCADE
      );
    `);
    logStep("EMAIL", "email_attachments table initialized");

    // Create email_categories table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_categories (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        color VARCHAR(7) DEFAULT '#808080'
      );
    `);
    logStep("EMAIL", "email_categories table initialized");

    // Create email_category_assignments table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_category_assignments (
        email_id VARCHAR(36) NOT NULL,
        category_id VARCHAR(36) NOT NULL,
        assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (email_id, category_id),
        FOREIGN KEY (email_id) REFERENCES company_emails(id) ON DELETE CASCADE,
        FOREIGN KEY (category_id) REFERENCES email_categories(id) ON DELETE CASCADE
      );
    `);
    logStep("EMAIL", "email_category_assignments table initialized");

    // Create company_name_aliases table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS company_name_aliases (
        id VARCHAR(36) PRIMARY KEY,
        company_id VARCHAR(36) NOT NULL,
        alias VARCHAR(255) NOT NULL,
        UNIQUE (company_id, alias),
        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
      );
    `);
    logStep("EMAIL", "company_name_aliases table initialized");

    // Create email_sync_logs table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_sync_logs (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        integration_id VARCHAR(36) NOT NULL,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP,
        emails_processed INT DEFAULT 0,
        emails_matched INT DEFAULT 0,
        status ENUM('running', 'completed', 'failed') DEFAULT 'running',
        error_message TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (integration_id) REFERENCES user_email_integrations(id)
      );
    `);
    logStep("EMAIL", "email_sync_logs table initialized");

    // Create default email categories
    const defaultCategories = [
      { id: uuidv4(), name: 'Application Confirmation', description: 'Emails confirming your job application', color: '#4CAF50' },
      { id: uuidv4(), name: 'Interview Request', description: 'Emails requesting an interview', color: '#2196F3' },
      { id: uuidv4(), name: 'Rejection', description: 'Job application rejections', color: '#F44336' },
      { id: uuidv4(), name: 'Offer', description: 'Job offers', color: '#9C27B0' },
      { id: uuidv4(), name: 'Follow-up', description: 'Follow-up communications', color: '#FF9800' }
    ];

    // Check if categories exist, add if not
    const [existingCategories] = await connection.query('SELECT COUNT(*) AS count FROM email_categories');
    if (existingCategories[0].count === 0) {
      for (const category of defaultCategories) {
        await connection.query(
          'INSERT INTO email_categories (id, name, description, color) VALUES (?, ?, ?, ?)',
          [category.id, category.name, category.description, category.color]
        );
      }
      logStep("EMAIL", "Default email categories created");
    }

    // Create attachments directory
    await fs.mkdir(path.join(__dirname, 'uploads', 'email-attachments'), { recursive: true });
    logStep("EMAIL", "Email attachments directory created or verified");

    connection.release();
    logSuccess("EMAIL", "Email integration database initialization complete");
    return true;
  } catch (error) {
    logError("EMAIL", "Failed to initialize email integration database", error);
    throw error;
  }
}

// ===== Helper Functions =====

// Get OAuth URL for a provider
function getOAuthUrl(provider) {
  if (provider === 'google') {
    const oauth2Client = new google.auth.OAuth2(
      oauthProviders.google.clientId,
      oauthProviders.google.clientSecret,
      oauthProviders.google.redirectUri
    );

    return oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: oauthProviders.google.scope
    });
  } else if (provider === 'outlook') {
    const baseUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
    const params = new URLSearchParams({
      client_id: oauthProviders.outlook.clientId,
      response_type: 'code',
      redirect_uri: oauthProviders.outlook.redirectUri,
      scope: oauthProviders.outlook.scope.join(' '),
      response_mode: 'query'
    });

    return `${baseUrl}?${params.toString()}`;
  }

  throw new Error(`Unsupported provider: ${provider}`);
}

// Exchange auth code for tokens
async function getTokensFromCode(provider, code) {
  if (provider === 'google') {
    const oauth2Client = new google.auth.OAuth2(
      oauthProviders.google.clientId,
      oauthProviders.google.clientSecret,
      oauthProviders.google.redirectUri
    );

    const { tokens } = await oauth2Client.getToken(code);
    return tokens;
  } else if (provider === 'outlook') {
    const tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    const params = new URLSearchParams({
      client_id: oauthProviders.outlook.clientId,
      client_secret: oauthProviders.outlook.clientSecret,
      code: code,
      redirect_uri: oauthProviders.outlook.redirectUri,
      grant_type: 'authorization_code'
    });

    const response = await axios.post(tokenUrl, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    return {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expiry_date: Date.now() + (response.data.expires_in * 1000)
    };
  }

  throw new Error(`Unsupported provider: ${provider}`);
}

// Get user email from provider
async function getUserEmail(provider, token) {
  if (provider === 'google') {
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: token });
    
    const userInfo = await google.oauth2('v2').userinfo.get({
      auth: oauth2Client
    });
    
    return userInfo.data.email;
  } else if (provider === 'outlook') {
    const response = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    return response.data.mail || response.data.userPrincipalName;
  }
  
  throw new Error(`Unsupported provider: ${provider}`);
}

// Refresh tokens if expired
async function refreshTokens(integration) {
  try {
    if (integration.provider === 'google') {
      const oauth2Client = new google.auth.OAuth2(
        oauthProviders.google.clientId,
        oauthProviders.google.clientSecret,
        oauthProviders.google.redirectUri
      );
      
      oauth2Client.setCredentials({
        refresh_token: encryption.decrypt(integration.refresh_token)
      });
      
      const { tokens } = await oauth2Client.refreshToken(
        encryption.decrypt(integration.refresh_token)
      );
      
      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token || encryption.decrypt(integration.refresh_token),
        expiry_date: tokens.expiry_date
      };
    } else if (integration.provider === 'outlook') {
      const tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
      const params = new URLSearchParams({
        client_id: oauthProviders.outlook.clientId,
        client_secret: oauthProviders.outlook.clientSecret,
        refresh_token: encryption.decrypt(integration.refresh_token),
        redirect_uri: oauthProviders.outlook.redirectUri,
        grant_type: 'refresh_token'
      });
      
      const response = await axios.post(tokenUrl, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      return {
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token || encryption.decrypt(integration.refresh_token),
        expiry_date: Date.now() + (response.data.expires_in * 1000)
      };
    }
    
    throw new Error(`Unsupported provider: ${integration.provider}`);
  } catch (error) {
    logError("EMAIL", `Failed to refresh tokens for ${integration.provider}`, error);
    throw error;
  }
}

// Check if tokens need refreshing and do so if needed
async function ensureFreshTokens(db, integration) {
  try {
    // Check if token is expired or about to expire (10 minutes buffer)
    const tokenExpiry = new Date(integration.token_expiry).getTime();
    const now = Date.now();
    const expiryBuffer = 10 * 60 * 1000; // 10 minutes
    
    if (tokenExpiry - now < expiryBuffer) {
      logStep("EMAIL", `Refreshing tokens for ${integration.provider} (${integration.email_address})`);
      
      const newTokens = await refreshTokens(integration);
      
      // Update tokens in database
      await db.query(`
        UPDATE user_email_integrations 
        SET 
          auth_token = ?, 
          refresh_token = ?, 
          token_expiry = ?, 
          updated_at = NOW(),
          integration_status = 'active',
          error_message = NULL
        WHERE id = ?
      `, [
        encryption.encrypt(newTokens.access_token),
        newTokens.refresh_token ? encryption.encrypt(newTokens.refresh_token) : integration.refresh_token,
        new Date(newTokens.expiry_date),
        integration.id
      ]);
      
      // Return updated integration
      return {
        ...integration,
        auth_token: encryption.encrypt(newTokens.access_token),
        refresh_token: newTokens.refresh_token ? encryption.encrypt(newTokens.refresh_token) : integration.refresh_token,
        token_expiry: new Date(newTokens.expiry_date),
        integration_status: 'active',
        error_message: null
      };
    }
    
    return integration;
  } catch (error) {
    // Update integration status to error
    await db.query(`
      UPDATE user_email_integrations 
      SET 
        integration_status = 'error',
        error_message = ?
      WHERE id = ?
    `, [
      error.message,
      integration.id
    ]);
    
    throw error;
  }
}

// Fetch emails from Google Gmail
async function fetchGmailEmails(accessToken, options = {}) {
  try {
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: accessToken });
    
    // Default options
    const searchOptions = {
      maxResults: options.maxResults || 100,
      q: options.query || '',
      pageToken: options.pageToken || null
    };
    
    // Get list of messages
    const response = await gmail.users.messages.list({
      auth: oauth2Client,
      userId: 'me',
      maxResults: searchOptions.maxResults,
      q: searchOptions.q,
      pageToken: searchOptions.pageToken
    });
    
    const messages = response.data.messages || [];
    const nextPageToken = response.data.nextPageToken || null;
    
    // Get full message details
    const emails = [];
    for (const message of messages) {
      const fullMessage = await gmail.users.messages.get({
        auth: oauth2Client,
        userId: 'me',
        id: message.id,
        format: 'full'
      });
      
      // Extract headers
      const headers = fullMessage.data.payload.headers;
      const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || '(No Subject)';
      const from = headers.find(h => h.name.toLowerCase() === 'from')?.value || '';
      const to = headers.find(h => h.name.toLowerCase() === 'to')?.value || '';
      const date = headers.find(h => h.name.toLowerCase() === 'date')?.value || '';
      
      // Extract body - handle multipart
      let body = '';
      if (fullMessage.data.payload.parts) {
        const textPart = fullMessage.data.payload.parts.find(part => 
          part.mimeType === 'text/plain' || part.mimeType === 'text/html'
        );
        
        if (textPart && textPart.body.data) {
          body = Buffer.from(textPart.body.data, 'base64').toString('utf-8');
        }
      } else if (fullMessage.data.payload.body && fullMessage.data.payload.body.data) {
        body = Buffer.from(fullMessage.data.payload.body.data, 'base64').toString('utf-8');
      }
      
      // Extract attachments
      const attachments = [];
      if (fullMessage.data.payload.parts) {
        for (const part of fullMessage.data.payload.parts) {
          if (part.filename && part.filename.length > 0) {
            attachments.push({
              filename: part.filename,
              mimeType: part.mimeType,
              size: part.body.size,
              attachmentId: part.body.attachmentId
            });
          }
        }
      }
      
      emails.push({
        id: message.id,
        threadId: fullMessage.data.threadId,
        subject,
        from,
        to,
        date: new Date(date),
        body,
        attachments,
        raw: fullMessage.data
      });
    }
    
    return {
      emails,
      nextPageToken
    };
  } catch (error) {
    logError("EMAIL", "Failed to fetch Gmail emails", error);
    throw error;
  }
}

// Fetch emails from Outlook/Office365
async function fetchOutlookEmails(accessToken, options = {}) {
  try {
    // Default options
    const searchOptions = {
      top: options.maxResults || 100,
      skip: options.skip || 0,
      filter: options.filter || ''
    };
    
    let url = 'https://graph.microsoft.com/v1.0/me/messages';
    const params = new URLSearchParams();
    
    params.append('$top', searchOptions.top);
    
    if (searchOptions.skip > 0) {
      params.append('$skip', searchOptions.skip);
    }
    
    if (searchOptions.filter) {
      params.append('$filter', searchOptions.filter);
    }
    
    params.append('$orderby', 'receivedDateTime desc');
    params.append('$select', 'id,subject,from,toRecipients,receivedDateTime,body,hasAttachments');
    
    url = `${url}?${params.toString()}`;
    
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const messages = response.data.value || [];
    
    // Extract the 'next' link if available
    let nextLink = null;
    if (response.data['@odata.nextLink']) {
      nextLink = response.data['@odata.nextLink'];
    }
    
    // Process messages
    const emails = messages.map(msg => {
      return {
        id: msg.id,
        threadId: msg.conversationId,
        subject: msg.subject || '(No Subject)',
        from: msg.from?.emailAddress?.address || '',
        to: msg.toRecipients?.map(r => r.emailAddress.address).join(', ') || '',
        date: new Date(msg.receivedDateTime),
        body: msg.body?.content || '',
        hasAttachments: msg.hasAttachments,
        raw: msg
      };
    });
    
    return {
      emails,
      nextLink
    };
  } catch (error) {
    logError("EMAIL", "Failed to fetch Outlook emails", error);
    throw error;
  }
}

// Get company matches from email content
async function matchCompaniesToEmail(db, userId, email) {
  try {
    // Get all companies that user has applied to
    const [companies] = await db.query(`
      SELECT c.id, c.name
      FROM companies c
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE v.user_id = ? AND v.status = 'applied'
    `, [userId]);
    
    if (companies.length === 0) {
      return [];
    }
    
    // Get company aliases
    const [aliases] = await db.query(`
      SELECT ca.company_id, ca.alias
      FROM company_name_aliases ca
      JOIN companies c ON ca.company_id = c.id
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE v.user_id = ? AND v.status = 'applied'
    `, [userId]);
    
    // Create map of company ID to name and aliases
    const companyMap = new Map();
    
    for (const company of companies) {
      companyMap.set(company.id, {
        id: company.id,
        name: company.name,
        aliases: []
      });
    }
    
    // Add aliases to company map
    for (const alias of aliases) {
      if (companyMap.has(alias.company_id)) {
        companyMap.get(alias.company_id).aliases.push(alias.alias);
      }
    }
    
    // Check for matches in email content
    const matches = [];
    const emailText = `${email.subject} ${email.from} ${email.body}`.toLowerCase();
    
    for (const [id, company] of companyMap.entries()) {
      // Check company name
      if (emailText.includes(company.name.toLowerCase())) {
        matches.push(id);
        continue;
      }
      
      // Check aliases
      for (const alias of company.aliases) {
        if (emailText.includes(alias.toLowerCase())) {
          matches.push(id);
          break;
        }
      }
    }
    
    return [...new Set(matches)]; // Remove duplicates
  } catch (error) {
    logError("EMAIL", "Failed to match companies to email", error);
    throw error;
  }
}

// Save email to database
async function saveEmailToDatabase(db, userId, email, companyId) {
  try {
    // Create new email record
    const emailId = uuidv4();
    
    // Save email
    await db.query(`
      INSERT INTO company_emails (
        id, user_id, company_id, email_id, subject, sender, received_date, content, is_read
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      emailId,
      userId,
      companyId,
      email.id,
      email.subject,
      email.from,
      email.date,
      email.body,
      false
    ]);
    
    // Handle email threading
    // First try to find existing thread with same subject for this company
    const [threads] = await db.query(`
      SELECT id, message_count 
      FROM email_threads 
      WHERE user_id = ? AND company_id = ? AND thread_subject = ?
      LIMIT 1
    `, [userId, companyId, email.subject]);
    
    if (threads.length > 0) {
      // Update existing thread
      const threadId = threads[0].id;
      const newCount = threads[0].message_count + 1;
      
      await db.query(`
        UPDATE email_threads 
        SET message_count = ?, last_update = ? 
        WHERE id = ?
      `, [newCount, email.date, threadId]);
    } else {
      // Create new thread
      const threadId = uuidv4();
      
      await db.query(`
        INSERT INTO email_threads (
          id, user_id, company_id, thread_subject, last_update, message_count
        ) VALUES (?, ?, ?, ?, ?, ?)
      `, [
        threadId,
        userId,
        companyId,
        email.subject,
        email.date,
        1
      ]);
    }
    
    // Handle attachments if there are any
    if (email.attachments && email.attachments.length > 0) {
      for (const attachment of email.attachments) {
        const attachmentId = uuidv4();
        const storagePath = `uploads/email-attachments/${attachmentId}-${attachment.filename}`;
        
        await db.query(`
          INSERT INTO email_attachments (
            id, email_id, filename, content_type, size, storage_path
          ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
          attachmentId,
          emailId,
          attachment.filename,
          attachment.mimeType,
          attachment.size,
          storagePath
        ]);
      }
    }
    
    return emailId;
  } catch (error) {
    logError("EMAIL", "Failed to save email to database", error);
    throw error;
  }
}

// Process emails for a user
async function processEmails(db, userId, integrationId) {
  try {
    // Get integration details
    const [integrations] = await db.query(`
      SELECT * FROM user_email_integrations WHERE id = ? AND user_id = ?
    `, [integrationId, userId]);
    
    if (integrations.length === 0) {
      throw new Error('Email integration not found');
    }
    
    const integration = integrations[0];
    
    // Create sync log
    const syncLogId = uuidv4();
    await db.query(`
      INSERT INTO email_sync_logs (
        id, user_id, integration_id, start_time, status
      ) VALUES (?, ?, ?, NOW(), 'running')
    `, [syncLogId, userId, integrationId]);
    
    // Refresh tokens if needed
    const freshIntegration = await ensureFreshTokens(db, integration);
    const accessToken = encryption.decrypt(freshIntegration.auth_token);
    
    // Initialize counters
    let emailsProcessed = 0;
    let emailsMatched = 0;
    
    // Fetch emails based on provider
    let emails = [];
    let hasMore = true;
    let pageToken = null;
    let skip = 0;
    
    // Determine the date since when to fetch emails
    let sinceDate = new Date();
    if (integration.last_sync_time) {
      sinceDate = new Date(integration.last_sync_time);
    } else {
      // If first sync, get emails from last 30 days
      sinceDate.setDate(sinceDate.getDate() - 30);
    }
    
    const sinceDateStr = sinceDate.toISOString();
    
    try {
      while (hasMore && emailsProcessed < 500) { // Limit to 500 emails per sync
        let result;
        
        if (integration.provider === 'google') {
          // For Gmail, use the after: query parameter with the date
          const query = `after:${sinceDate.getFullYear()}/${sinceDate.getMonth() + 1}/${sinceDate.getDate()}`;
          
          result = await fetchGmailEmails(accessToken, {
            maxResults: 50,
            pageToken,
            query
          });
          
          emails = result.emails;
          pageToken = result.nextPageToken;
          hasMore = !!pageToken;
        } else if (integration.provider === 'outlook') {
          // For Outlook, use the receivedDateTime filter
          const filter = `receivedDateTime ge ${sinceDateStr}`;
          
          result = await fetchOutlookEmails(accessToken, {
            maxResults: 50,
            skip,
            filter
          });
          
          emails = result.emails;
          hasMore = !!result.nextLink;
          skip += 50;
        }
        
        // Process fetched emails
        for (const email of emails) {
          emailsProcessed++;
          
          // Match companies in email
          const companyMatches = await matchCompaniesToEmail(db, userId, email);
          
          // Save matches to database
          for (const companyId of companyMatches) {
            await saveEmailToDatabase(db, userId, email, companyId);
            emailsMatched++;
          }
        }
        
        // Update sync log progress
        await db.query(`
          UPDATE email_sync_logs 
          SET emails_processed = ?, emails_matched = ? 
          WHERE id = ?
        `, [emailsProcessed, emailsMatched, syncLogId]);
        
        if (!hasMore || emails.length === 0) {
          break;
        }
      }
      
      // Update last sync time
      await db.query(`
        UPDATE user_email_integrations 
        SET last_sync_time = NOW() 
        WHERE id = ?
      `, [integrationId]);
      
      // Complete sync log
      await db.query(`
        UPDATE email_sync_logs 
        SET 
          end_time = NOW(), 
          status = 'completed',
          emails_processed = ?,
          emails_matched = ?
        WHERE id = ?
      `, [emailsProcessed, emailsMatched, syncLogId]);
      
      return {
        success: true,
        emailsProcessed,
        emailsMatched
      };
    } catch (error) {
      // Update sync log with error
      await db.query(`
        UPDATE email_sync_logs 
        SET 
          end_time = NOW(), 
          status = 'failed',
          error_message = ?,
          emails_processed = ?,
          emails_matched = ?
        WHERE id = ?
      `, [error.message, emailsProcessed, emailsMatched, syncLogId]);
      
      throw error;
    }
  } catch (error) {
    logError("EMAIL", "Failed to process emails", error);
    throw error;
  }
}

// ===== API Routes =====

// Get all integrations for a user
router.get('/integrations', async (req, res) => {
  try {
    const [integrations] = await req.db.query(`
      SELECT id, email_address, provider, integration_status, last_sync_time, created_at, updated_at, error_message
      FROM user_email_integrations
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [req.user.id]);
    
    res.json({ integrations });
  } catch (error) {
    logError("EMAIL", "Failed to get user integrations", error);
    res.status(500).json({ error: 'Failed to get integrations' });
  }
});

// Remove an integration
router.delete('/integrations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if integration exists and belongs to user
    const [integrations] = await req.db.query(`
      SELECT * FROM user_email_integrations WHERE id = ? AND user_id = ?
    `, [id, req.user.id]);
    
    if (integrations.length === 0) {
      return res.status(404).json({ error: 'Integration not found' });
    }
    
    // Delete integration
    await req.db.query(`
      DELETE FROM user_email_integrations WHERE id = ?
    `, [id]);
    
    res.json({ success: true, message: 'Integration removed successfully' });
  } catch (error) {
    logError("EMAIL", "Failed to remove integration", error);
    res.status(500).json({ error: 'Failed to remove integration' });
  }
});

// Start authentication flow for a provider
router.get('/auth/:provider', (req, res) => {
  try {
    const { provider } = req.params;
    
    if (!['google', 'outlook'].includes(provider)) {
      return res.status(400).json({ error: 'Unsupported email provider' });
    }
    
    // Store user ID in session for callback
    if (!req.session) {
      req.session = {};
    }
    
    req.session.userId = req.user.id;
    
    // Generate OAuth URL
    const authUrl = getOAuthUrl(provider);
    
    res.json({ authUrl });
  } catch (error) {
    logError("EMAIL", `Failed to start ${req.params.provider} auth flow`, error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// OAuth callback handler
router.get('/auth/:provider/callback', async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, error, state } = req.query;
    
    if (error) {
      return res.redirect(`/email-integration.html?error=${encodeURIComponent(error)}`);
    }
    
    if (!code) {
      return res.redirect('/email-integration.html?error=No+authorization+code+provided');
    }
    
    // Get userId from state or session
    let userId;
    if (state) {
      // State should contain encrypted user ID
      try {
        userId = encryption.decrypt(state);
      } catch (err) {
        return res.redirect('/email-integration.html?error=Invalid+state+parameter');
      }
    } else if (req.session && req.session.userId) {
      userId = req.session.userId;
    } else {
      return res.redirect('/email-integration.html?error=Session+expired');
    }
    
    // Exchange code for tokens
    const tokens = await getTokensFromCode(provider, code);
    
    // Get user email
    const email = await getUserEmail(provider, tokens.access_token);
    
    // Check if integration already exists
    const [existingIntegrations] = await req.db.query(`
      SELECT * FROM user_email_integrations 
      WHERE user_id = ? AND email_address = ?
    `, [userId, email]);
    
    if (existingIntegrations.length > 0) {
      // Update existing integration
      await req.db.query(`
        UPDATE user_email_integrations 
        SET 
          auth_token = ?, 
          refresh_token = ?, 
          token_expiry = ?,
          provider = ?,
          integration_status = 'active',
          updated_at = NOW(),
          error_message = NULL
        WHERE id = ?
      `, [
        encryption.encrypt(tokens.access_token),
        encryption.encrypt(tokens.refresh_token),
        new Date(tokens.expiry_date),
        provider,
        existingIntegrations[0].id
      ]);
      
      return res.redirect('/email-integration.html?success=Email+integration+updated');
    }
    
    // Create new integration
    const integrationId = uuidv4();
    
    await req.db.query(`
      INSERT INTO user_email_integrations (
        id, user_id, email_address, provider, auth_token, refresh_token, token_expiry, integration_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      integrationId,
      userId,
      email,
      provider,
      encryption.encrypt(tokens.access_token),
      encryption.encrypt(tokens.refresh_token),
      new Date(tokens.expiry_date)
    ]);
    
    res.redirect('/email-integration.html?success=Email+integration+added');
  } catch (error) {
    logError("EMAIL", `OAuth callback error for ${req.params.provider}`, error);
    res.redirect(`/email-integration.html?error=${encodeURIComponent(error.message)}`);
  }
});

// Manually sync emails for an integration
router.post('/sync/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if integration exists and belongs to user
    const [integrations] = await req.db.query(`
      SELECT * FROM user_email_integrations WHERE id = ? AND user_id = ?
    `, [id, req.user.id]);
    
    if (integrations.length === 0) {
      return res.status(404).json({ error: 'Integration not found' });
    }
    
    // Start sync process (non-blocking)
    processEmails(req.db, req.user.id, id)
      .then(result => {
        logSuccess("EMAIL", `Email sync completed for user ${req.user.id}: ${result.emailsMatched} emails matched`);
      })
      .catch(error => {
        logError("EMAIL", `Email sync failed for user ${req.user.id}`, error);
      });
    
    res.json({ 
      success: true, 
      message: 'Email sync started',
      syncInProgress: true
    });
  } catch (error) {
    logError("EMAIL", "Failed to start email sync", error);
    res.status(500).json({ error: 'Failed to start email sync' });
  }
});

// Get sync status
router.get('/sync-status/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get latest sync log
    const [logs] = await req.db.query(`
      SELECT * FROM email_sync_logs 
      WHERE integration_id = ? AND user_id = ?
      ORDER BY start_time DESC
      LIMIT 1
    `, [id, req.user.id]);
    
    if (logs.length === 0) {
      return res.json({ 
        status: 'no_sync',
        message: 'No sync has been performed yet'
      });
    }
    
    const log = logs[0];
    
    res.json({
      status: log.status,
      startTime: log.start_time,
      endTime: log.end_time,
      emailsProcessed: log.emails_processed,
      emailsMatched: log.emails_matched,
      error: log.error_message
    });
  } catch (error) {
    logError("EMAIL", "Failed to get sync status", error);
    res.status(500).json({ error: 'Failed to get sync status' });
  }
});

// Get company emails
router.get('/company/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Get company details
    const [companies] = await req.db.query(`
      SELECT c.*, v.status, v.notes 
      FROM companies c
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE c.id = ? AND v.user_id = ?
    `, [id, req.user.id]);
    
    if (companies.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Get emails for this company
    const [emails] = await req.db.query(`
      SELECT e.*, a.id as has_attachments
      FROM company_emails e
      LEFT JOIN email_attachments a ON e.id = a.email_id
      WHERE e.company_id = ? AND e.user_id = ?
      GROUP BY e.id
      ORDER BY e.received_date DESC
      LIMIT ? OFFSET ?
    `, [id, req.user.id, limit, offset]);
    
    // Get total count for pagination
    const [countResult] = await req.db.query(`
      SELECT COUNT(*) as total
      FROM company_emails
      WHERE company_id = ? AND user_id = ?
    `, [id, req.user.id]);
    
    // Get email threads
    const [threads] = await req.db.query(`
      SELECT * 
      FROM email_threads
      WHERE company_id = ? AND user_id = ?
      ORDER BY last_update DESC
    `, [id, req.user.id]);
    
    res.json({
      company: companies[0],
      emails,
      threads,
      pagination: {
        total: countResult[0].total,
        page,
        limit,
        pages: Math.ceil(countResult[0].total / limit)
      }
    });
  } catch (error) {
    logError("EMAIL", "Failed to get company emails", error);
    res.status(500).json({ error: 'Failed to get company emails' });
  }
});

// Get email details including attachments
router.get('/email/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get email details
    const [emails] = await req.db.query(`
      SELECT e.*, c.name as company_name
      FROM company_emails e
      JOIN companies c ON e.company_id = c.id
      WHERE e.id = ? AND e.user_id = ?
    `, [id, req.user.id]);
    
    if (emails.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Get attachments
    const [attachments] = await req.db.query(`
      SELECT id, filename, content_type, size
      FROM email_attachments
      WHERE email_id = ?
    `, [id]);
    
    // Mark as read if not already
    if (!emails[0].is_read) {
      await req.db.query(`
        UPDATE company_emails SET is_read = TRUE WHERE id = ?
      `, [id]);
    }
    
    res.json({
      email: emails[0],
      attachments
    });
  } catch (error) {
    logError("EMAIL", "Failed to get email details", error);
    res.status(500).json({ error: 'Failed to get email details' });
  }
});

// Get attachment file
router.get('/attachment/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get attachment details
    const [attachments] = await req.db.query(`
      SELECT a.*, e.user_id
      FROM email_attachments a
      JOIN company_emails e ON a.email_id = e.id
      WHERE a.id = ?
    `, [id]);
    
    if (attachments.length === 0) {
      return res.status(404).json({ error: 'Attachment not found' });
    }
    
    // Check if attachment belongs to user
    if (attachments[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if file exists
    const filePath = path.join(__dirname, attachments[0].storage_path);
    
    try {
      await fs.access(filePath);
    } catch (error) {
      return res.status(404).json({ error: 'Attachment file not found' });
    }
    
    // Set content type
    res.setHeader('Content-Type', attachments[0].content_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${attachments[0].filename}"`);
    
    // Stream file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } catch (error) {
    logError("EMAIL", "Failed to get attachment", error);
    res.status(500).json({ error: 'Failed to get attachment' });
  }
});

// Add company name alias
router.post('/company/:id/alias', async (req, res) => {
  try {
    const { id } = req.params;
    const { alias } = req.body;
    
    if (!alias) {
      return res.status(400).json({ error: 'Alias is required' });
    }
    
    // Check if company exists and user has applied
    const [companies] = await req.db.query(`
      SELECT c.* 
      FROM companies c
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE c.id = ? AND v.user_id = ? AND v.status = 'applied'
    `, [id, req.user.id]);
    
    if (companies.length === 0) {
      return res.status(404).json({ error: 'Company not found or not applied' });
    }
    
    // Check if alias already exists
    const [aliases] = await req.db.query(`
      SELECT * FROM company_name_aliases WHERE company_id = ? AND alias = ?
    `, [id, alias]);
    
    if (aliases.length > 0) {
      return res.status(400).json({ error: 'Alias already exists for this company' });
    }
    
    // Add alias
    const aliasId = uuidv4();
    
    await req.db.query(`
      INSERT INTO company_name_aliases (id, company_id, alias)
      VALUES (?, ?, ?)
    `, [aliasId, id, alias]);
    
    res.json({ 
      success: true, 
      message: 'Alias added successfully',
      alias: {
        id: aliasId,
        company_id: id,
        alias
      }
    });
  } catch (error) {
    logError("EMAIL", "Failed to add company alias", error);
    res.status(500).json({ error: 'Failed to add company alias' });
  }
});

// Get company aliases
router.get('/company/:id/aliases', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if company exists and user has applied
    const [companies] = await req.db.query(`
      SELECT c.* 
      FROM companies c
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE c.id = ? AND v.user_id = ?
    `, [id, req.user.id]);
    
    if (companies.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Get aliases
    const [aliases] = await req.db.query(`
      SELECT * FROM company_name_aliases WHERE company_id = ?
    `, [id]);
    
    res.json({ aliases });
  } catch (error) {
    logError("EMAIL", "Failed to get company aliases", error);
    res.status(500).json({ error: 'Failed to get company aliases' });
  }
});

// Delete company alias
router.delete('/alias/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if alias exists and belongs to a company the user has applied to
    const [aliases] = await req.db.query(`
      SELECT a.* 
      FROM company_name_aliases a
      JOIN companies c ON a.company_id = c.id
      JOIN user_career_page_visits v ON c.id = v.company_id
      WHERE a.id = ? AND v.user_id = ?
    `, [id, req.user.id]);
    
    if (aliases.length === 0) {
      return res.status(404).json({ error: 'Alias not found' });
    }
    
    // Delete alias
    await req.db.query(`
      DELETE FROM company_name_aliases WHERE id = ?
    `, [id]);
    
    res.json({ 
      success: true, 
      message: 'Alias deleted successfully' 
    });
  } catch (error) {
    logError("EMAIL", "Failed to delete alias", error);
    res.status(500).json({ error: 'Failed to delete alias' });
  }
});

// Get email categories
router.get('/categories', async (req, res) => {
  try {
    // Get all categories
    const [categories] = await req.db.query(`
      SELECT * FROM email_categories
      ORDER BY name
    `);
    
    res.json({ categories });
  } catch (error) {
    logError("EMAIL", "Failed to get email categories", error);
    res.status(500).json({ error: 'Failed to get email categories' });
  }
});

// Assign email to category
router.post('/email/:id/category/:categoryId', async (req, res) => {
  try {
    const { id, categoryId } = req.params;
    
    // Check if email exists and belongs to user
    const [emails] = await req.db.query(`
      SELECT * FROM company_emails WHERE id = ? AND user_id = ?
    `, [id, req.user.id]);
    
    if (emails.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Check if category exists
    const [categories] = await req.db.query(`
      SELECT * FROM email_categories WHERE id = ?
    `, [categoryId]);
    
    if (categories.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    // Check if already assigned
    const [assignments] = await req.db.query(`
      SELECT * FROM email_category_assignments WHERE email_id = ? AND category_id = ?
    `, [id, categoryId]);
    
    if (assignments.length > 0) {
      return res.status(400).json({ error: 'Email already assigned to this category' });
    }
    
    // Assign email to category
    await req.db.query(`
      INSERT INTO email_category_assignments (email_id, category_id)
      VALUES (?, ?)
    `, [id, categoryId]);
    
    res.json({ 
      success: true, 
      message: 'Email assigned to category' 
    });
  } catch (error) {
    logError("EMAIL", "Failed to assign email to category", error);
    res.status(500).json({ error: 'Failed to assign email to category' });
  }
});

// Remove email from category
router.delete('/email/:id/category/:categoryId', async (req, res) => {
  try {
    const { id, categoryId } = req.params;
    
    // Check if email exists and belongs to user
    const [emails] = await req.db.query(`
      SELECT * FROM company_emails WHERE id = ? AND user_id = ?
    `, [id, req.user.id]);
    
    if (emails.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Remove assignment
    await req.db.query(`
      DELETE FROM email_category_assignments 
      WHERE email_id = ? AND category_id = ?
    `, [id, categoryId]);
    
    res.json({ 
      success: true, 
      message: 'Email removed from category' 
    });
  } catch (error) {
    logError("EMAIL", "Failed to remove email from category", error);
    res.status(500).json({ error: 'Failed to remove email from category' });
  }
});

// Get emails by category
router.get('/category/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Check if category exists
    const [categories] = await req.db.query(`
      SELECT * FROM email_categories WHERE id = ?
    `, [id]);
    
    if (categories.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    // Get emails in this category
    const [emails] = await req.db.query(`
      SELECT e.*, c.name as company_name
      FROM company_emails e
      JOIN companies c ON e.company_id = c.id
      JOIN email_category_assignments a ON e.id = a.email_id
      WHERE a.category_id = ? AND e.user_id = ?
      ORDER BY e.received_date DESC
      LIMIT ? OFFSET ?
    `, [id, req.user.id, limit, offset]);
    
    // Get total count for pagination
    const [countResult] = await req.db.query(`
      SELECT COUNT(*) as total
      FROM company_emails e
      JOIN email_category_assignments a ON e.id = a.email_id
      WHERE a.category_id = ? AND e.user_id = ?
    `, [id, req.user.id]);
    
    res.json({
      category: categories[0],
      emails,
      pagination: {
        total: countResult[0].total,
        page,
        limit,
        pages: Math.ceil(countResult[0].total / limit)
      }
    });
  } catch (error) {
    logError("EMAIL", "Failed to get emails by category", error);
    res.status(500).json({ error: 'Failed to get emails by category' });
  }
});

// Get dashboard stats
router.get('/dashboard', async (req, res) => {
  try {
    // Get total emails
    const [totalEmails] = await req.db.query(`
      SELECT COUNT(*) as count
      FROM company_emails
      WHERE user_id = ?
    `, [req.user.id]);
    
    // Get unread emails
    const [unreadEmails] = await req.db.query(`
      SELECT COUNT(*) as count
      FROM company_emails
      WHERE user_id = ? AND is_read = FALSE
    `, [req.user.id]);
    
    // Get emails by company (top 5)
    const [companiesWithEmails] = await req.db.query(`
      SELECT c.id, c.name, COUNT(e.id) as email_count
      FROM companies c
      JOIN company_emails e ON c.id = e.company_id
      WHERE e.user_id = ?
      GROUP BY c.id
      ORDER BY email_count DESC
      LIMIT 5
    `, [req.user.id]);
    
    // Get recent emails
    const [recentEmails] = await req.db.query(`
      SELECT e.*, c.name as company_name
      FROM company_emails e
      JOIN companies c ON e.company_id = c.id
      WHERE e.user_id = ?
      ORDER BY e.received_date DESC
      LIMIT 5
    `, [req.user.id]);
    
    // Get active integrations
    const [integrations] = await req.db.query(`
      SELECT COUNT(*) as count
      FROM user_email_integrations
      WHERE user_id = ? AND integration_status = 'active'
    `, [req.user.id]);
    
    res.json({
      stats: {
        totalEmails: totalEmails[0].count,
        unreadEmails: unreadEmails[0].count,
        companiesWithEmails: companiesWithEmails,
        activeIntegrations: integrations[0].count
      },
      recentEmails
    });
  } catch (error) {
    logError("EMAIL", "Failed to get dashboard stats", error);
    res.status(500).json({ error: 'Failed to get dashboard stats' });
  }
});

// ===== ADMIN API ROUTES =====

// Get all integrations stats (admin only)
router.get('/admin/stats', async (req, res) => {
  try {
    // Check if admin password is provided
    const adminPassword = req.query.adminPassword || req.headers['admin-password'];
    
    if (adminPassword !== 'FSaX54SB') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Get total integrations
    const [totalIntegrations] = await req.db.query(`
      SELECT COUNT(*) as count FROM user_email_integrations
    `);
    
    // Get active integrations
    const [activeIntegrations] = await req.db.query(`
      SELECT COUNT(*) as count FROM user_email_integrations
      WHERE integration_status = 'active'
    `);
    
    // Get integrations by provider
    const [providerStats] = await req.db.query(`
      SELECT provider, COUNT(*) as count
      FROM user_email_integrations
      GROUP BY provider
    `);
    
    // Get total emails
    const [totalEmails] = await req.db.query(`
      SELECT COUNT(*) as count FROM company_emails
    `);
    
    // Get recent sync logs
    const [recentSyncs] = await req.db.query(`
      SELECT l.*, u.email as user_email, i.email_address, i.provider
      FROM email_sync_logs l
      JOIN users u ON l.user_id = u.id
      JOIN user_email_integrations i ON l.integration_id = i.id
      ORDER BY l.start_time DESC
      LIMIT 10
    `);
    
    res.json({
      stats: {
        totalIntegrations: totalIntegrations[0].count,
        activeIntegrations: activeIntegrations[0].count,
        providerStats,
        totalEmails: totalEmails[0].count
      },
      recentSyncs
    });
  } catch (error) {
    logError("EMAIL", "Failed to get admin stats", error);
    res.status(500).json({ error: 'Failed to get admin stats' });
  }
});

// Background job to periodically check and sync emails for all active integrations
async function syncAllActiveIntegrations(db) {
  try {
    logStep("EMAIL", "Starting scheduled sync for all active integrations");
    
    // Get all active integrations
    const [integrations] = await db.query(`
      SELECT * FROM user_email_integrations
      WHERE integration_status = 'active'
    `);
    
    logStep("EMAIL", `Found ${integrations.length} active integrations to sync`);
    
    // Process each integration
    for (const integration of integrations) {
      try {
        logStep("EMAIL", `Syncing emails for user ${integration.user_id}, integration ${integration.id}`);
        
        await processEmails(db, integration.user_id, integration.id);
        
        logSuccess("EMAIL", `Successfully synced emails for integration ${integration.id}`);
      } catch (error) {
        logError("EMAIL", `Failed to sync emails for integration ${integration.id}`, error);
        
        // Update integration status to error
        await db.query(`
          UPDATE user_email_integrations 
          SET 
            integration_status = 'error',
            error_message = ?
          WHERE id = ?
        `, [error.message, integration.id]);
      }
    }
    
    logSuccess("EMAIL", "Completed scheduled sync for all active integrations");
  } catch (error) {
    logError("EMAIL", "Failed to run scheduled sync", error);
  }
}

// Export router and init function
module.exports = {
  router,
  initEmailDatabase,
  syncAllActiveIntegrations
};
