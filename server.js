const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "Africonnect-secret-key-2024";

// ✅ Enhanced Middleware
app.use(cors({
    origin: [
        "http://localhost:8080",  // ✅ frontend server
        "http://localhost:3000", 
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501"
    ],
    credentials: true
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ✅ Example routes (you already have your own, just showing structure)
app.get("/api/roles", (req, res) => {
    res.json(["admin", "user", "guest"]);
});

app.post("/api/register", (req, res) => {
    const { name, email } = req.body;
    res.json({ message: `User ${name} (${email}) registered successfully!` });
});

// ✅ Start server
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});


// MongoDB Connection with multiple databases
const mainDB = mongoose.createConnection(process.env.MONGODB_URI || 'mongodb://localhost:27017/Afriserve', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const customerDB = mongoose.createConnection(process.env.MONGODB_URI || 'mongodb://localhost:27017/Africonnect_Customers', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const businessDB = mongoose.createConnection(process.env.MONGODB_URI || 'mongodb://localhost:27017/Africonnect_Businesses', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const providerDB = mongoose.createConnection(process.env.MONGODB_URI || 'mongodb://localhost:27017/Africonnect_Providers', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const wholesalerDB = mongoose.createConnection(process.env.MONGODB_URI || 'mongodb://localhost:27017/Africonnect_Wholesalers', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Function to connect to databases
async function connectDatabases() {
    try {
        await mainDB.asPromise();
        console.log('✅ Main Database Connected');
        
        await customerDB.asPromise();
        console.log('✅ Customer Database Connected');
        
        await businessDB.asPromise();
        console.log('✅ Business Database Connected');
        
        await providerDB.asPromise();
        console.log('✅ Provider Database Connected');
        
        await wholesalerDB.asPromise();
        console.log('✅ Wholesaler Database Connected');
    } catch (error) {
        console.error('❌ Database Connection Error:', error);
        process.exit(1);
    }
}

connectDatabases();

// Enhanced User Schema for main database
const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true,
        minlength: [2, 'Full name must be at least 2 characters'],
        maxlength: [100, 'Full name cannot exceed 100 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        match: [/^\+?[\d\s\-\(\)]{10,}$/, 'Please enter a valid phone number']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    role: {
        type: String,
        enum: {
            values: ['Customer', 'BusinessOwner', 'Wholesaler', 'ServiceProvider', 'NotSelected'],
            message: 'Invalid role selected'
        },
        default: 'NotSelected'
    },
    themePreference: {
        type: String,
        enum: ['default', 'blue', 'purple', 'dark', 'green'],
        default: 'default'
    },
    profileCompleted: {
        type: Boolean,
        default: false
    },
    profileData: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'roleModel'
    },
    roleModel: {
        type: String,
        enum: ['Customer', 'Business', 'ServiceProvider', 'Wholesaler', null],
        default: null
    },
    uniqueId: {
        type: String,
        unique: true,
        sparse: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Add password comparison method to user schema
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new Error('Error comparing passwords');
    }
};

// Add JWT token generation method to user schema
userSchema.methods.generateAuthToken = function() {
    return jwt.sign(
        { 
            userId: this._id, 
            email: this.email,
            role: this.role,
            theme: this.themePreference
        },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
    const user = this.toObject();
    delete user.password;
    return user;
};

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(new Error('Error hashing password'));
    }
});

// Role-specific schemas
const customerSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    dateOfBirth: {
        type: Date,
        required: true
    },
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other'],
        required: true
    },
    address: {
        street: String,
        city: String,
        state: String,
        zipCode: String,
        country: {
            type: String,
            default: 'South Africa'
        }
    },
    preferences: {
        notifications: { type: Boolean, default: true },
        newsletter: { type: Boolean, default: false },
        smsAlerts: { type: Boolean, default: true }
    },
    profileImage: String,
    emergencyContact: {
        name: String,
        phone: String,
        relationship: String
    }
}, {
    timestamps: true
});

const businessSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    businessName: {
        type: String,
        required: true,
        trim: true
    },
    businessType: {
        type: String,
        required: true,
        enum: ['Retail', 'Service', 'Manufacturing', 'Food', 'Healthcare', 'Education', 'Other']
    },
    registrationNumber: {
        type: String,
        required: true,
        unique: true
    },
    taxId: String,
    yearEstablished: Number,
    numberOfEmployees: {
        type: String,
        enum: ['1-10', '11-50', '51-200', '201-500', '500+']
    },
    businessAddress: {
        street: String,
        city: String,
        state: String,
        zipCode: String,
        country: {
            type: String,
            default: 'South Africa'
        }
    },
    contactPerson: {
        name: String,
        position: String,
        phone: String,
        email: String
    },
    businessHours: {
        monday: { open: String, close: String },
        tuesday: { open: String, close: String },
        wednesday: { open: String, close: String },
        thursday: { open: String, close: String },
        friday: { open: String, close: String },
        saturday: { open: String, close: String },
        sunday: { open: String, close: String }
    },
    services: [{
        name: String,
        description: String,
        price: Number,
        duration: Number,
        category: String
    }],
    certifications: [{
        name: String,
        issuingAuthority: String,
        issueDate: Date,
        expiryDate: Date
    }],
    bankDetails: {
        bankName: String,
        accountNumber: String,
        accountHolder: String,
        branchCode: String
    },
    socialMedia: {
        website: String,
        facebook: String,
        twitter: String,
        instagram: String,
        linkedin: String
    },
    businessDescription: String,
    profileImage: String,
    coverImage: String
}, {
    timestamps: true
});

const serviceProviderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    professionalTitle: {
        type: String,
        required: true
    },
    specialization: {
        type: String,
        required: true
    },
    yearsOfExperience: {
        type: Number,
        required: true
    },
    skills: [String],
    qualifications: [{
        institution: String,
        qualification: String,
        year: Number,
        field: String
    }],
    certifications: [{
        name: String,
        issuingAuthority: String,
        year: Number
    }],
    serviceAreas: [String],
    hourlyRate: Number,
    availability: {
        monday: { available: Boolean, hours: [String] },
        tuesday: { available: Boolean, hours: [String] },
        wednesday: { available: Boolean, hours: [String] },
        thursday: { available: Boolean, hours: [String] },
        friday: { available: Boolean, hours: [String] },
        saturday: { available: Boolean, hours: [String] },
        sunday: { available: Boolean, hours: [String] }
    },
    portfolio: [{
        title: String,
        description: String,
        image: String,
        date: Date
    }],
    insurance: {
        hasInsurance: Boolean,
        provider: String,
        policyNumber: String,
        expiryDate: Date
    },
    backgroundCheck: {
        verified: Boolean,
        verifiedBy: String,
        verificationDate: Date
    },
    languages: [String],
    travelRadius: Number,
    equipment: [String],
    references: [{
        name: String,
        relationship: String,
        phone: String,
        email: String
    }]
}, {
    timestamps: true
});

const wholesalerSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    companyName: {
        type: String,
        required: true
    },
    businessType: {
        type: String,
        required: true,
        enum: ['Manufacturer', 'Distributor', 'Supplier', 'Importer', 'Exporter']
    },
    registrationNumber: {
        type: String,
        required: true,
        unique: true
    },
    vatNumber: String,
    yearEstablished: Number,
    companySize: {
        type: String,
        enum: ['Small (1-50)', 'Medium (51-200)', 'Large (201-1000)', 'Enterprise (1000+)']
    },
    productCategories: [String],
    brandsCarried: [String],
    minimumOrder: Number,
    paymentTerms: String,
    deliveryOptions: [String],
    warehouseLocations: [{
        address: String,
        city: String,
        state: String,
        zipCode: String,
        country: String
    }],
    contactPersons: [{
        name: String,
        position: String,
        phone: String,
        email: String,
        department: String
    }],
    certifications: [{
        name: String,
        issuingAuthority: String,
        issueDate: Date,
        expiryDate: Date
    }],
    qualityStandards: [String],
    exportCapabilities: {
        canExport: Boolean,
        countries: [String],
        documents: [String]
    },
    bankDetails: {
        bankName: String,
        accountNumber: String,
        accountHolder: String,
        branchCode: String,
        swiftCode: String
    },
    tradeReferences: [{
        company: String,
        contact: String,
        phone: String,
        email: String,
        yearsTrading: Number
    }],
    catalog: [{
        productName: String,
        category: String,
        brand: String,
        description: String,
        price: Number,
        moq: Number,
        images: [String]
    }]
}, {
    timestamps: true
});

// Create models for each database
const User = mainDB.model('User', userSchema);
const Customer = customerDB.model('Customer', customerSchema);
const Business = businessDB.model('Business', businessSchema);
const ServiceProvider = providerDB.model('ServiceProvider', serviceProviderSchema);
const Wholesaler = wholesalerDB.model('Wholesaler', wholesalerSchema);

// Unique ID generation functions
function generateUniqueId(role, businessInitials = null, userChosenNumber = null) {
    const timestamp = Date.now().toString().slice(-4);
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    
    switch(role) {
        case 'Customer':
            return `CU-${timestamp}${random}`;
            
        case 'BusinessOwner':
            const bizInitials = businessInitials ? businessInitials.slice(0, 3).toUpperCase() : 'BIZ';
            const bizNumber = userChosenNumber ? userChosenNumber.toString().padStart(4, '0') : '0000';
            return `BIZ-${bizInitials}${bizNumber}-${random}`;
            
        case 'ServiceProvider':
            return `SP-${timestamp}${random}`;
            
        case 'Wholesaler':
            const wsInitials = businessInitials ? businessInitials.slice(0, 2).toUpperCase() : 'WS';
            const wsNumber = userChosenNumber ? userChosenNumber.toString().padStart(4, '0') : '0000';
            return `W-${wsInitials}${wsNumber}-${random}`;
            
        default:
            return `USR-${timestamp}${random}`;
    }
}

// Enhanced Auth middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ 
                success: false,
                message: 'Access token required' 
            });
        }

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ 
                    success: false,
                    message: 'Invalid or expired token' 
                });
            }
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
};

// Validation middleware
const validateRegistration = [
    body('fullName')
        .trim()
        .notEmpty().withMessage('Full name is required')
        .isLength({ min: 2, max: 100 }).withMessage('Full name must be between 2-100 characters')
        .escape(),
    body('email')
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail()
        .custom(async (email) => {
            const user = await User.findOne({ email });
            if (user) {
                throw new Error('Email already registered');
            }
        }),
    body('phone')
        .trim()
        .notEmpty().withMessage('Phone number is required')
        .matches(/^\+?[\d\s\-\(\)]{10,}$/).withMessage('Please enter a valid phone number'),
    body('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
];

const validateLogin = [
    body('email')
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
    body('password')
        .notEmpty().withMessage('Password is required')
];

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true,
        status: 'OK', 
        message: 'Africonnect API is running smoothly',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Register endpoint
app.post('/api/register', validateRegistration, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false,
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const { fullName, email, phone, password, themePreference = 'default' } = req.body;

        const user = new User({
            fullName,
            email,
            phone,
            password,
            themePreference
        });

        await user.save();

        const token = user.generateAuthToken();

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                themePreference: user.themePreference,
                profileCompleted: user.profileCompleted
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: 'Validation error',
                errors: Object.values(error.errors).map(err => err.message)
            });
        }
        
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        res.status(500).json({ 
            success: false,
            message: 'Internal server error during registration' 
        });
    }
});

// Login endpoint
app.post('/api/login', validateLogin, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false,
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const { email, password } = req.body;

        const user = await User.findOne({ email, isActive: true });
        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: 'Invalid email or password' 
            });
        }

        // Use the comparePassword method that's now defined on the schema
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false,
                message: 'Invalid email or password' 
            });
        }

        user.lastLogin = new Date();
        await user.save();

        const token = user.generateAuthToken();

        // Check if user needs to complete profile
        const needsProfileCompletion = !user.profileCompleted || user.role === 'NotSelected';

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                themePreference: user.themePreference,
                profileCompleted: user.profileCompleted,
                uniqueId: user.uniqueId
            },
            needsProfileCompletion
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Internal server error during login' 
        });
    }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'User not found' 
            });
        }

        let profileData = null;
        
        // Fetch role-specific data
        if (user.profileCompleted && user.roleModel) {
            switch(user.roleModel) {
                case 'Customer':
                    profileData = await Customer.findOne({ userId: user._id });
                    break;
                case 'Business':
                    profileData = await Business.findOne({ userId: user._id });
                    break;
                case 'ServiceProvider':
                    profileData = await ServiceProvider.findOne({ userId: user._id });
                    break;
                case 'Wholesaler':
                    profileData = await Wholesaler.findOne({ userId: user._id });
                    break;
            }
        }

        res.json({ 
            success: true,
            user,
            profileData
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error fetching user profile' 
        });
    }
});

// Update user role and create profile
app.post('/api/complete-profile', authenticateToken, async (req, res) => {
    try {
        const { role, profileData, businessInitials, userChosenNumber } = req.body;
        const userId = req.user.userId;

        if (!['Customer', 'BusinessOwner', 'Wholesaler', 'ServiceProvider'].includes(role)) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid role specified' 
            });
        }

        // Generate unique ID
        const uniqueId = generateUniqueId(role, businessInitials, userChosenNumber);

        // Update user role and unique ID
        const user = await User.findByIdAndUpdate(
            userId,
            { 
                role,
                uniqueId,
                profileCompleted: true,
                roleModel: role === 'BusinessOwner' ? 'Business' : role
            },
            { new: true }
        );

        let roleProfile = null;
        let roleModel = null;

        // Create role-specific profile
        switch(role) {
            case 'Customer':
                roleProfile = new Customer({
                    userId: user._id,
                    ...profileData
                });
                roleModel = 'Customer';
                break;

            case 'BusinessOwner':
                roleProfile = new Business({
                    userId: user._id,
                    ...profileData
                });
                roleModel = 'Business';
                break;

            case 'ServiceProvider':
                roleProfile = new ServiceProvider({
                    userId: user._id,
                    ...profileData
                });
                roleModel = 'ServiceProvider';
                break;

            case 'Wholesaler':
                roleProfile = new Wholesaler({
                    userId: user._id,
                    ...profileData
                });
                roleModel = 'Wholesaler';
                break;
        }

        await roleProfile.save();

        // Update user with profile reference
        user.profileData = roleProfile._id;
        user.roleModel = roleModel;
        await user.save();

        // Generate new token with updated info
        const token = user.generateAuthToken();

        res.json({
            success: true,
            message: 'Profile completed successfully',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                uniqueId: user.uniqueId,
                profileCompleted: user.profileCompleted
            },
            profileData: roleProfile
        });

    } catch (error) {
        console.error('Profile completion error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error completing profile' 
        });
    }
});

// Update user theme preference
app.patch('/api/update-theme', authenticateToken, async (req, res) => {
    try {
        const { theme } = req.body;
        
        if (!['default', 'blue', 'purple', 'dark', 'green'].includes(theme)) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid theme specified' 
            });
        }

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { themePreference: theme },
            { new: true }
        );

        const token = user.generateAuthToken();

        res.json({
            success: true,
            message: 'Theme updated successfully',
            token,
            user
        });
    } catch (error) {
        console.error('Theme update error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error updating theme preference' 
        });
    }
});

// Get available themes
app.get('/api/themes', (req, res) => {
    res.json({
        success: true,
        themes: [
            {
                id: 'default',
                name: 'Sunset Orange',
                primary: '#FF6B00',
                secondary: '#00A859'
            },
            {
                id: 'blue',
                name: 'Ocean Blue',
                primary: '#2563EB',
                secondary: '#06B6D4'
            },
            {
                id: 'purple',
                name: 'Royal Purple',
                primary: '#7C3AED',
                secondary: '#EC4899'
            },
            {
                id: 'dark',
                name: 'Midnight Dark',
                primary: '#F59E0B',
                secondary: '#10B981'
            },
            {
                id: 'green',
                name: 'Forest Green',
                primary: '#059669',
                secondary: '#65A30D'
            }
        ]
    });
});

// Get user roles information - FIXED VERSION
app.get('/api/roles', (req, res) => {
    res.json({
        success: true,
        roles: [
            {
                id: 'Customer',
                name: 'Customer',
                description: 'Find and book services from trusted local businesses',
                icon: 'fas fa-user',
                benefits: [
                    'Browse verified service providers',
                    'Book appointments easily',
                    'Read reviews and ratings',
                    'Secure payment options',
                    'Real-time booking notifications'
                ]
            },
            {
                id: 'BusinessOwner',
                name: 'Business Owner',
                description: 'Grow your business by reaching new customers',
                icon: 'fas fa-store',
                benefits: [
                    'List your business services',
                    'Manage appointments and bookings',
                    'Receive customer reviews',
                    'Expand your customer base',
                    'Business analytics dashboard'
                ]
            },
            {
                id: 'ServiceProvider',
                name: 'Service Provider',
                description: 'Offer your skills and services to customers',
                icon: 'fas fa-tools',
                benefits: [
                    'Showcase your expertise',
                    'Set your own schedule',
                    'Build your reputation',
                    'Get paid for your services',
                    'Client management tools'
                ]
            },
            {
                id: 'Wholesaler',
                name: 'Wholesaler',
                description: 'Connect with businesses and service providers',
                icon: 'fas fa-boxes',
                benefits: [
                    'Reach business customers',
                    'Bulk order management',
                    'Business networking',
                    'Supply chain integration',
                    'Inventory tracking'
                ]
            }
        ]
    });
});

// Protected dashboard route
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Welcome to your dashboard',
            user,
            dashboardData: {
                notifications: 5,
                recentActivity: [],
                quickStats: {
                    totalBookings: 0,
                    completedServices: 0,
                    pendingRequests: 0,
                    revenue: 0
                }
            }
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error accessing dashboard' 
        });
    }
});

// Logout endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Logout successful'
    });
});

// Additional utility endpoints

// Check authentication status
app.get('/api/check-auth', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            authenticated: true,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                themePreference: user.themePreference,
                profileCompleted: user.profileCompleted,
                uniqueId: user.uniqueId
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Authentication check failed'
        });
    }
});

// Update user profile
app.patch('/api/update-profile', authenticateToken, async (req, res) => {
    try {
        const { fullName, phone } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { fullName, phone },
            { new: true, runValidators: true }
        );

        res.json({
            success: true,
            message: 'Profile updated successfully',
            user
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating profile'
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Africonnect Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🎨 Theme API: http://localhost:${PORT}/api/themes`);
    console.log(`👥 Roles API: http://localhost:${PORT}/api/roles`);
    console.log(`🔐 Auth API: http://localhost:${PORT}/api/login`);
});