const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const bcrypt = require('bcrypt');

// Import configuration
const logger = require('./config/logger');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const dashboardRoutes = require('./routes/dashboard');
const materialRoutes = require('./routes/materials');
const productRoutes = require('./routes/products');
const supplierRoutes = require('./routes/suppliers');
const customerRoutes = require('./routes/customers');
const bomRoutes = require('./routes/bom');
const poRoutes = require('./routes/pos');
const workOrderRoutes = require('./routes/workOrders');
const salesRoutes = require('./routes/sales');
const stockRoutes = require('./routes/stock');

// Import middleware
const { errorHandler, notFound } = require('./middleware/errorHandler');

// Initialize Express app
const app = express();

console.log('=== INITIALIZING EXPRESS APP ===');
console.log('Loading middleware and routes...');

// ============================================================================
// TRUST PROXY (Important for Railway)
// ============================================================================

// Trust Railway proxy - must be set before other middleware
app.set('trust proxy', 1);

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Helmet - Security headers
app.use(
  helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production',
    crossOriginEmbedderPolicy: process.env.NODE_ENV === 'production',
  })
);

// CORS Configuration - Updated for Railway + Vercel (Production + Preview)
const corsOptions = {
  origin: (origin, callback) => {
    console.log('CORS Check - Origin:', origin);
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      console.log('CORS: Allowing request with no origin');
      return callback(null, true);
    }
    
    // Get allowed origins from environment variable
    const envOrigins = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
      : [];
    
    // Allowed patterns (combining env + regex for Vercel previews)
    const allowedPatterns = [
      ...envOrigins, // From environment variable
      /^https:\/\/inventory-apl-frontend.*\.vercel\.app$/, // All Vercel deployments (production + preview)
      'http://localhost:3000', // Local development
      'http://localhost:5173', // Vite local development
    ];
    
    console.log('CORS Check - Allowed Patterns:', {
      envOrigins,
      hasVercelPattern: true,
      totalPatterns: allowedPatterns.length
    });
    
    // Check if origin matches any pattern
    const isAllowed = allowedPatterns.some(pattern => {
      if (typeof pattern === 'string') {
        return origin === pattern;
      }
      if (pattern instanceof RegExp) {
        return pattern.test(origin);
      }
      return false;
    });
    
    if (isAllowed) {
      console.log('CORS: Origin allowed');
      callback(null, true);
    } else {
      console.log('CORS: Origin blocked');
      callback(new Error(`Not allowed by CORS: ${origin}`));
    }
  },
  credentials: process.env.CORS_CREDENTIALS === 'true',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// ============================================================================
// RATE LIMITING
// ============================================================================

// General rate limiter
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 500, // 500 requests per minute
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  skipSuccessfulRequests: true,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
  },
  handler: (req, res) => {
    const retryAfter = Math.ceil(req.rateLimit.resetTime.getTime() / 1000 - Date.now() / 1000);
    const minutes = Math.ceil(retryAfter / 60);
    
    res.status(429).json({
      success: false,
      message: 'Too many authentication attempts, please try again later.',
      retryAfter: retryAfter, // in seconds
      retryAfterMinutes: minutes,
      resetTime: req.rateLimit.resetTime
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============================================================================
// BODY PARSING & COMPRESSION
// ============================================================================

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression()); // Compress responses

// ============================================================================
// EMERGENCY ROUTES (MUST BE BEFORE RATE LIMITER!)
// ============================================================================

// Only enable emergency routes if explicitly allowed
if (process.env.ALLOW_EMERGENCY === 'true' || process.env.NODE_ENV !== 'production') {
  console.log('⚠️  EMERGENCY ROUTES ENABLED ⚠️');
  
  // Create admin user
  app.post('/api/emergency-create-admin', async (req, res) => {
    try {
      const { User } = require('./models');
      
      // Check if admin exists
      const existingAdmin = await User.findOne({ where: { username: 'admin' } });
      
      if (existingAdmin) {
        return res.json({
          success: true,
          message: 'Admin user already exists',
          data: {
            username: 'admin',
            note: 'Use existing password'
          }
        });
      }

      // Create admin user
      const hashedPassword = await bcrypt.hash('admin123', 10);
      
      await User.create({
        username: 'admin',
        password: hashedPassword,
        full_name: 'System Administrator',
        role: 'admin',
        email: 'admin@example.com',
        is_active: true
      });

      console.log('✅ Admin user created successfully');

      res.json({
        success: true,
        message: 'Admin user created successfully',
        data: {
          username: 'admin',
          password: 'admin123',
          role: 'admin',
          email: 'admin@example.com'
        }
      });
    } catch (error) {
      console.error('❌ Create admin error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create admin user',
        error: error.message
      });
    }
  });

  // Setup database schema
  app.get('/api/emergency-setup', async (req, res) => {
    try {
      const { sequelize } = require('./utils/database');
      
      // Force sync all tables
      await sequelize.sync({ alter: true });
      
      console.log('✅ Database schema setup completed');
      
      res.json({
        success: true,
        message: 'Database schema setup completed'
      });
    } catch (error) {
      console.error('❌ Setup error:', error);
      res.status(500).json({
        success: false,
        message: 'Setup failed',
        error: error.message
      });
    }
  });

  // Insert sample data
  app.post('/api/emergency-insert-data', async (req, res) => {
    try {
      const { User } = require('./models');
      
      // Create admin first if not exists
      const adminExists = await User.findOne({ where: { username: 'admin' } });
      if (!adminExists) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await User.create({
          username: 'admin',
          password: hashedPassword,
          full_name: 'System Administrator',
          role: 'admin',
          email: 'admin@example.com',
          is_active: true
        });
      }

      console.log('✅ Sample data inserted successfully');

      res.json({
        success: true,
        message: 'Sample data inserted successfully',
        data: {
          users: 1
        }
      });
    } catch (error) {
      console.error('❌ Insert data error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to insert sample data',
        error: error.message
      });
    }
  });

  console.log('✓ Emergency routes registered at /api/emergency-*');
}

// ============================================================================
// LOGGING
// ============================================================================

// HTTP request logging
if (process.env.ENABLE_MORGAN_LOGGING === 'true') {
  app.use(
    morgan('combined', {
      stream: logger.stream,
      skip: (req) => req.url === '/health' || req.url === '/ping', // Skip health check logs
    })
  );
}

// Request logging middleware
if (process.env.ENABLE_REQUEST_LOGGING === 'true') {
  app.use((req, res, next) => {
    logger.info({
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
    next();
  });
}

// ============================================================================
// STATIC FILES (if needed)
// ============================================================================

if (process.env.UPLOAD_DIR) {
  app.use('/uploads', express.static(path.join(__dirname, '..', process.env.UPLOAD_DIR)));
}

// ============================================================================
// HEALTH CHECK & INFO ENDPOINTS
// ============================================================================

// Health check with database status
app.get('/health', async (req, res) => {
  const { sequelize } = require('./utils/database');
  
  const healthcheck = {
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB',
    },
    database: {
      status: 'unknown',
      type: process.env.DB_DIALECT || 'mysql',
    },
  };

  try {
    // Check database connection
    await sequelize.authenticate();
    healthcheck.database.status = 'connected';
    res.status(200).json(healthcheck);
  } catch (error) {
    healthcheck.success = false;
    healthcheck.status = 'unhealthy';
    healthcheck.database.status = 'disconnected';
    healthcheck.database.error = error.message;
    res.status(503).json(healthcheck);
  }
});

// Simple ping endpoint for basic monitoring
app.get('/ping', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'pong',
    timestamp: new Date().toISOString(),
  });
});

// Root endpoint with API info
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Factory Inventory Management API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/health',
      ping: '/ping',
      api: '/api',
      auth: '/api/auth',
      materials: '/api/materials',
      products: '/api/products',
      suppliers: '/api/suppliers',
      customers: '/api/customers',
      bom: '/api/bom',
      purchaseOrders: '/api/purchase-orders',
      workOrders: '/api/work-orders',
      salesOrders: '/api/sales-orders',
      stock: '/api/stock',
    },
    documentation: process.env.ENABLE_SWAGGER === 'true' ? '/api-docs' : null,
  });
});

app.get('/api', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Factory Inventory Management API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      materials: '/api/materials',
      products: '/api/products',
      suppliers: '/api/suppliers',
      customers: '/api/customers',
      bom: '/api/bom',
      purchaseOrders: '/api/purchase-orders',
      workOrders: '/api/work-orders',
      salesOrders: '/api/sales-orders',
      stock: '/api/stock',
    },
    documentation: process.env.ENABLE_SWAGGER === 'true' ? '/api-docs' : null,
  });
});

// ============================================================================
// API ROUTES
// ============================================================================

const API_PREFIX = process.env.API_PREFIX || '/api';

console.log(`=== REGISTERING API ROUTES ===`);
console.log(`API Prefix: ${API_PREFIX}`);

// Apply rate limiting to API routes
app.use(API_PREFIX, generalLimiter);

// Auth routes with stricter rate limiting
console.log(`✓ Registering route: ${API_PREFIX}/auth`);
app.use(`${API_PREFIX}/auth`, authLimiter, authRoutes);

// Dashboard routes (accessible by all authenticated users)
console.log(`✓ Registering route: ${API_PREFIX}/dashboard`);
app.use(`${API_PREFIX}/dashboard`, dashboardRoutes);

// User management routes (admin only)
console.log(`✓ Registering route: ${API_PREFIX}/users`);
app.use(`${API_PREFIX}/users`, userRoutes);

// Resource routes
console.log(`✓ Registering route: ${API_PREFIX}/materials`);
app.use(`${API_PREFIX}/materials`, materialRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/products`);
app.use(`${API_PREFIX}/products`, productRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/suppliers`);
app.use(`${API_PREFIX}/suppliers`, supplierRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/customers`);
app.use(`${API_PREFIX}/customers`, customerRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/bom`);
app.use(`${API_PREFIX}/bom`, bomRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/purchase-orders`);
app.use(`${API_PREFIX}/purchase-orders`, poRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/work-orders`);
app.use(`${API_PREFIX}/work-orders`, workOrderRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/sales-orders`);
app.use(`${API_PREFIX}/sales-orders`, salesRoutes);
console.log(`✓ Registering route: ${API_PREFIX}/stock`);
app.use(`${API_PREFIX}/stock`, stockRoutes);

console.log('=== ALL ROUTES REGISTERED ===');

// ============================================================================
// API DOCUMENTATION (Swagger) - Optional
// ============================================================================

if (process.env.ENABLE_SWAGGER === 'true') {
  // Swagger setup would go here
  // const swaggerUi = require('swagger-ui-express');
  // const swaggerDocument = require('./swagger.json');
  // app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
  
  logger.info('📚 Swagger documentation is enabled but not yet configured');
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler - must be before error handler
app.use(notFound);

// Global error handler - must be last
app.use(errorHandler);

// ============================================================================
// EXPORT APP
// ============================================================================

module.exports = app;
