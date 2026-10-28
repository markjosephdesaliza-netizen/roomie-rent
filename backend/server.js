const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware with 50MB limits for multi-image support
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL || false 
    : '*', // Allows local testing freely, restricts in production
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Setup multer to store uploaded files temporarily in memory
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Helper function to upload buffer or base64 data to Cloudinary
const uploadToCloudinary = (fileInput, folderName = 'roomie_rent') => {
  return new Promise((resolve, reject) => {
    // If it's already a regular http URL or null/undefined, return as is
    if (!fileInput || typeof fileInput === 'string' && fileInput.startsWith('http')) {
      return resolve(fileInput);
    }

    // Handle incoming Buffer (from multipart form) or Base64 data URI string
    let uploadSource = fileInput;
    if (typeof fileInput === 'string' && fileInput.startsWith('data:image')) {
      uploadSource = fileInput; // Cloudinary upload_stream handles data URIs or we can use uploader.upload
    }

    const options = { folder: folderName };

    if (Buffer.isBuffer(fileInput)) {
      const uploadStream = cloudinary.uploader.upload_stream(
        options,
        (error, result) => {
          if (error) return reject(error);
          resolve(result.secure_url);
        }
      );
      uploadStream.end(fileInput);
    } else {
      // Direct string upload (base64 data URI or path)
      cloudinary.uploader.upload(fileInput, options, (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      });
    }
  });
};

// Helper function to process arrays of images (e.g. listing image galleries)
const processImagesForCloudinary = async (imageInput, folderName) => {
  if (!imageInput) return null;

  // If it's an array of images
  if (Array.isArray(imageInput)) {
    const uploadedUrls = [];
    for (const img of imageInput) {
      const url = await uploadToCloudinary(img, folderName);
      uploadedUrls.push(url);
    }
    return uploadedUrls;
  }

  // If it's a JSON stringified array
  if (typeof imageInput === 'string') {
    try {
      const parsed = JSON.parse(imageInput);
      if (Array.isArray(parsed)) {
        const uploadedUrls = [];
        for (const img of parsed) {
          const url = await uploadToCloudinary(img, folderName);
          uploadedUrls.push(url);
        }
        return JSON.stringify(uploadedUrls);
      }
    } catch (e) {
      // Not a JSON string, treat as single image string
    }
  }

  // Single image string (base64 or URL)
  return await uploadToCloudinary(imageInput, folderName);
};

// Authentication Middleware Helper
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: 'Access Denied: No authentication token provided.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token.' });
  }
}

function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ message: 'Access Denied: Administrator privileges required.' });
    }
  });
}

// Serve frontend static files
const frontendPath = path.resolve(__dirname, '../frontend');
app.use(express.static(frontendPath));

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(frontendPath, 'login.html'));
});

app.get('/reset-password.html', (req, res) => {
  res.sendFile(path.join(frontendPath, 'reset-password.html'));
});

// PostgreSQL Pool Connection (Supports both local variables and cloud DATABASE_URL)
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      }
    : {
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      }
);

// Email Transporter Configuration (using environment variables or fallback to console logs)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-email-app-password'
  }
});

// Test Connection
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      message: 'Database connected successfully!',
      time: result.rows[0].now
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Heartbeat Endpoint to update real-time activity status
app.post('/api/users/heartbeat', async (req, res) => {
  try {
    const { userId } = req.body;
    if (userId) {
      await pool.query('UPDATE users SET last_active = NOW() WHERE id = $1', [userId]);
    }
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register API (Supports Renter & Landlord with ID Verification & Cloudinary Uploads)
app.post('/api/auth/register', async (req, res) => {
  try {
    let {
      name,
      email,
      phone,
      city,
      barangay,
      password,
      role,
      id_type,
      id_number,
      id_front_image,
      id_back_image,
      property_proof_image
    } = req.body;

    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({
        message: 'Email is already registered'
      });
    }

    // Upload ID and verification images to Cloudinary
    console.log("☁️ Uploading verification assets to Cloudinary...");
    const frontImgUrl = await uploadToCloudinary(id_front_image, 'roomie_rent/verifications');
    const backImgUrl = await uploadToCloudinary(id_back_image, 'roomie_rent/verifications');
    const propertyProofUrl = await uploadToCloudinary(property_proof_image, 'roomie_rent/verifications');

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Landlords start unverified (is_verified = false) until approved by admin
    const isVerified = role === 'landlord' ? false : true;

    const newUser = await pool.query(
      `INSERT INTO users (
        full_name,
        email,
        phone_number,
        city,
        barangay,
        password_hash,
        role,
        id_type,
        id_number,
        id_front_image,
        id_back_image,
        property_proof_image,
        is_verified,
        last_active
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING
        id,
        full_name,
        email,
        phone_number,
        city,
        barangay,
        role,
        is_verified,
        created_at`,
      [
        name,
        email,
        phone || null,
        city || null,
        barangay || null,
        passwordHash,
        role || 'renter',
        id_type || null,
        id_number || null,
        frontImgUrl || null,
        backImgUrl || null,
        propertyProofUrl || null,
        isVerified
      ]
    );

    res.status(201).json({
      message: role === 'landlord' 
        ? 'Landlord account registered successfully! Please wait for admin verification before logging in.'
        : 'User registered successfully!',
      user: newUser.rows[0]
    });
  } catch (err) {
    console.error("❌ REGISTRATION ERROR:", err.message);
    res.status(500).json({
      message: 'Server error during registration: ' + err.message
    });
  }
});

// Login API (Strictly blocks unverified landlords, updates last_active, and issues JWT)
app.post('/api/auth/login', async (req, res) => {
  try {
    const {
      email,
      password,
      role
    } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    const user = result.rows[0];

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!isPasswordValid) {
      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    if (role && user.role !== role && user.role !== 'admin') {
      return res.status(400).json({
        message: `Account found, but it is not registered as a ${role}`
      });
    }

    // STRICT CHECK: If user is a landlord, verify their account approval status
    if (user.role === 'landlord') {
      if (user.is_verified === false || user.is_verified === 0 || user.is_verified === null) {
        return res.status(403).json({
          message: 'Access Denied: Your landlord account is pending admin verification. Please wait for the administrator to review and approve your ID credentials.'
        });
      }
    }

    // Update last_active on login
    await pool.query('UPDATE users SET last_active = NOW() WHERE id = $1', [user.id]);

    // Issue Real JWT Token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful!',
      token: token,
      user: {
        id: user.id,
        name: user.full_name,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone_number,
        phone_number: user.phone_number,
        role: user.role,
        is_verified: user.is_verified,
        profile_image: user.profile_image
      }
    });
  } catch (err) {
    console.error("❌ LOGIN ERROR:", err.message);
    res.status(500).json({
      message: 'Server error during login'
    });
  }
});

// Forgot Password API Endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) {
      return res.json({ message: 'If this email exists, password reset instructions have been sent.' });
    }

    const resetToken = Math.random().toString(36).substring(2) + Date.now().toString(36);
    const frontendUrl = process.env.FRONTEND_URL || 'https://roomie-rent.netlify.app';
    const resetLink = `${frontendUrl}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
      from: '"Roomie Rent Support" <support@roomierent.com>',
      to: email,
      subject: 'Password Reset Instructions - Roomie Rent',
      html: `
        <div style="font-family:sans-serif; padding: 20px; color: #1e293b;">
          <h2 style="color: #C85A32;">Roomie Rent Password Reset</h2>
          <p>You requested to reset your password. Kindly click the "Reset Password" button below to proceed:</p>
          <a href="${resetLink}" style="display:inline-block; background:#C85A32; color:#ffffff; padding:10px 20px; text-decoration:none; border-radius:8px; font-weight:bold; margin-top:10px;">Reset Password</a>
          <p style="font-size:12px; color:#64748b; margin-top:20px;">If you didn't request this, you can safely ignore this email.</p>
        </div>
      `
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (mailErr) {
      console.log('⚠️ Email transporter not configured or failed. Reset Link for development:', resetLink);
    }

    res.json({ message: 'Password reset instructions have been sent to your email!' });
  } catch (err) {
    console.error("❌ FORGOT PASSWORD ERROR:", err.message);
    res.status(500).json({ message: 'Server error during password reset request' });
  }
});

// Update Password API Endpoint (from reset page)
app.post('/api/auth/update-password', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and new password are required.' });
    }

    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(password, saltRounds);

    const updateRes = await pool.query(
      'UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id',
      [newPasswordHash, email]
    );

    if (updateRes.rows.length === 0) {
      return res.status(404).json({ message: 'User account not found.' });
    }

    res.json({ message: 'Password updated successfully!' });
  } catch (err) {
    console.error("❌ UPDATE PASSWORD ERROR:", err.message);
    res.status(500).json({ message: 'Server error while updating password.' });
  }
});

// GET All Users API (Includes live online calculation based on last 2 minutes activity)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        id, full_name, email, phone_number, role, city, barangay, 
        profile_image, id_type, id_number, id_front_image, id_back_image, 
        property_proof_image, is_verified, created_at, last_active,
        (last_active >= NOW() - INTERVAL '2 minutes') AS is_online
       FROM users 
       ORDER BY id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ FETCH USERS ERROR:", err.message);
    res.status(500).json({ message: 'Server error while fetching users' });
  }
});

// PUT Verify or Reject Landlord API (Admin Endpoint - Protected with verifyAdmin)
app.put('/api/admin/verify-landlord/:id', verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_verified } = req.body; // boolean true/false

    const updated = await pool.query(
      `UPDATE users 
       SET is_verified = $1 
       WHERE id = $2 AND role = 'landlord'
       RETURNING id, full_name, email, role, is_verified`,
      [is_verified, id]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ message: 'Landlord not found' });
    }

    const actionText = is_verified ? 'VERIFIED & APPROVED' : 'REJECTED';
    console.log(`🛡️ ADMIN ACTION: Landlord ${updated.rows[0].full_name} (ID: ${updated.rows[0].id}) account has been ${actionText}.`);

    res.json({
      message: is_verified ? 'Landlord account successfully verified and approved!' : 'Landlord account verification rejected.',
      user: updated.rows[0]
    });
  } catch (err) {
    console.error("❌ VERIFY LANDLORD ERROR:", err.message);
    res.status(500).json({ message: 'Server error while updating landlord verification status' });
  }
});

// DELETE User / Terminate Account API (Admin Endpoint for Scammers - Protected with verifyAdmin)
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Delete associated listings first if user is a landlord
    await pool.query('DELETE FROM listings WHERE landlord_id = $1', [id]);
    
    // Delete user record
    const deleted = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, full_name, email, role', [id]);

    if (deleted.rows.length === 0) {
      return res.status(404).json({ message: 'User account not found' });
    }

    // Terminal feedback log
    console.log(`🗑️ SUCCESS: Terminated account for ${deleted.rows[0].full_name} (ID: ${deleted.rows[0].id}) and cascaded related records.`);

    res.json({
      message: `Account for ${deleted.rows[0].full_name} has been successfully terminated and removed from the system.`,
      user: deleted.rows[0]
    });
  } catch (err) {
    console.error("❌ TERMINATE USER ERROR:", err.message);
    res.status(500).json({ message: 'Server error while terminating user account' });
  }
});


// GET User Profile API
app.get('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT
        id,
        full_name,
        email,
        phone_number,
        city,
        barangay,
        role,
        is_verified,
        profile_image,
        last_active
       FROM users
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ FETCH USER ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while fetching user profile'
    });
  }
});

// PUT Update User Profile API (With Cloudinary Image Upload)
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const {
      full_name,
      phone_number,
      city,
      barangay,
      profile_image
    } = req.body;

    let profileImageUrl = profile_image;
    if (profile_image && !profile_image.startsWith('http')) {
      console.log("☁️ Uploading new profile image to Cloudinary...");
      profileImageUrl = await uploadToCloudinary(profile_image, 'roomie_rent/profiles');
    }

    const updated = await pool.query(
      `UPDATE users
       SET
        full_name = COALESCE($1, full_name),
        phone_number = COALESCE($2, phone_number),
        city = COALESCE($3, city),
        barangay = COALESCE($4, barangay),
        profile_image = COALESCE($5, profile_image)
       WHERE id = $6
       RETURNING
        id,
        full_name,
        email,
        phone_number,
        city,
        barangay,
        role,
        is_verified,
        profile_image`,
      [
        full_name,
        phone_number,
        city,
        barangay,
        profileImageUrl,
        id
      ]
    );

    res.json({
      message: 'Profile updated successfully!',
      user: updated.rows[0]
    });
  } catch (err) {
    console.error("❌ UPDATE PROFILE ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while updating profile'
    });
  }
});

// PUT Change Password API
app.put('/api/users/:id/password', async (req, res) => {
  try {
    const { id } = req.params;

    const {
      current_password,
      new_password
    } = req.body;

    const userRes = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    const user = userRes.rows[0];

    const isPasswordValid = await bcrypt.compare(
      current_password,
      user.password_hash
    );

    if (!isPasswordValid) {
      return res.status(400).json({
        message: 'Current password is incorrect'
      });
    }

    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(
      new_password,
      saltRounds
    );

    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newPasswordHash, id]
    );

    res.json({
      message: 'Password changed successfully!'
    });
  } catch (err) {
    console.error("❌ CHANGE PASSWORD ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while changing password'
    });
  }
});

// GET All Listings API
app.get('/api/listings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent AS price,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude,
        created_at
      FROM listings
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({
      message: 'Server error while fetching listings'
    });
  }
});

// GET Listings by Landlord ID API
app.get('/api/listings/landlord/:landlordId', async (req, res) => {
  try {
    const { landlordId } = req.params;
    const result = await pool.query(`
      SELECT
        id,
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent AS price,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude,
        created_at
      FROM listings
      WHERE landlord_id = $1
      ORDER BY created_at DESC
    `, [landlordId]);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ FETCH LANDLORD LISTINGS ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while fetching landlord listings'
    });
  }
});

// GET Single Listing API
app.get('/api/listings/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `
      SELECT
        id,
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent AS price,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude,
        created_at
      FROM listings
      WHERE id = $1
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: 'Listing not found'
      });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({
      message: 'Server error while fetching room details'
    });
  }
});

// POST New Listing API (With Cloudinary Image Upload support)
app.post('/api/listings', upload.array('image_files', 10), async (req, res) => {
  try {
    let {
      landlord_id,
      title,
      city,
      barangay,
      monthly_rent,
      property_type,
      image_url,
      description,
      house_rules,
      status,
      latitude,
      longitude
    } = req.body;

    // Collect images from multer multipart files or base64 input fields
    let processedImages = [];
    
    if (req.files && req.files.length > 0) {
      console.log("☁️ Uploading multipart listing images to Cloudinary...");
      for (const file of req.files) {
        const cloudUrl = await uploadToCloudinary(file.buffer, 'roomie_rent/listings');
        processedImages.push(cloudUrl);
      }
    } else if (image_url) {
      console.log("☁️ Uploading listing images (base64/URLs) to Cloudinary...");
      const uploadedResult = await processImagesForCloudinary(image_url, 'roomie_rent/listings');
      if (Array.isArray(uploadedResult)) {
        processedImages = uploadedResult;
      } else if (uploadedResult) {
        processedImages.push(uploadedResult);
      }
    }

    const finalImagesString = processedImages.length > 0 
      ? JSON.stringify(processedImages) 
      : null;

    const newListing = await pool.query(
      `INSERT INTO listings (
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude
      )
      VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10, $11, $12
      )
      RETURNING
        id,
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent AS price,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude,
        created_at`,
      [
        landlord_id,
        title,
        city,
        barangay,
        monthly_rent,
        property_type,
        finalImagesString,
        description || null,
        house_rules || null,
        status || 'verified',
        latitude ? parseFloat(latitude) : null,
        longitude ? parseFloat(longitude) : null
      ]
    );

    res.status(201).json({
      message: 'Listing created successfully with Cloudinary images!',
      listing: newListing.rows[0]
    });
  } catch (err) {
    console.error("❌ CREATE LISTING ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while creating listing'
    });
  }
});

// PUT Edit/Update Listing API Route (With Cloudinary Image Upload support)
app.put('/api/listings/:id', upload.array('image_files', 10), async (req, res) => {
  try {
    const { id } = req.params;

    let {
      title,
      city,
      barangay,
      monthly_rent,
      property_type,
      image_url,
      description,
      house_rules,
      status,
      latitude,
      longitude
    } = req.body;

    let processedImages = [];
    if (req.files && req.files.length > 0) {
      console.log("☁️ Uploading updated multipart listing images to Cloudinary...");
      for (const file of req.files) {
        const cloudUrl = await uploadToCloudinary(file.buffer, 'roomie_rent/listings');
        processedImages.push(cloudUrl);
      }
    } else if (image_url) {
      const uploadedResult = await processImagesForCloudinary(image_url, 'roomie_rent/listings');
      if (Array.isArray(uploadedResult)) {
        processedImages = uploadedResult;
      } else if (uploadedResult) {
        processedImages.push(uploadedResult);
      }
    }

    let imageValue = processedImages.length > 0 
      ? JSON.stringify(processedImages) 
      : image_url;

    const parsedRent = parseFloat(monthly_rent);

    if (isNaN(parsedRent)) {
      return res.status(400).json({
        message: 'Invalid monthly rent amount'
      });
    }

    const updatedListing = await pool.query(
      `UPDATE listings
       SET
        title = $1,
        city = $2,
        barangay = $3,
        monthly_rent = $4,
        property_type = $5,
        image_url = COALESCE($6, image_url),
        description = $7,
        house_rules = $8,
        status = $9,
        latitude = $10,
        longitude = $11
       WHERE id = $12
       RETURNING
        id,
        title,
        city,
        monthly_rent AS price,
        property_type,
        image_url,
        description,
        house_rules,
        status,
        latitude,
        longitude`,
      [
        title,
        city,
        barangay || 'Central',
        parsedRent,
        property_type,
        imageValue || null,
        description || null,
        house_rules || null,
        status || 'verified',
        latitude ? parseFloat(latitude) : null,
        longitude ? parseFloat(longitude) : null,
        id
      ]
    );

    if (updatedListing.rows.length === 0) {
      return res.status(404).json({
        message: 'Listing not found'
      });
    }

    res.json({
      message: 'Listing updated successfully!',
      listing: updatedListing.rows[0]
    });
  } catch (err) {
    console.error("❌ UPDATE LISTING ERROR:", err.message);
    res.status(500).json({
      message: 'Server error while updating listing: ' + err.message
    });
  }
});

// DELETE Listing API
app.delete('/api/listings/:id', async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      'DELETE FROM listings WHERE id = $1',
      [id]
    );

    res.json({
      message: 'Listing deleted successfully'
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({
      message: 'Server error while deleting listing'
    });
  }
});

// --- THREADED INBOX & CONVERSATION API ROUTES ---

// POST: Submit a new inquiry
app.post('/api/inquiries', async (req, res) => {
  try {
    let {
      listing_id,
      renter_id,
      landlord_id,
      renter_name,
      renter_email,
      renter_phone,
      listing_title,
      listing_price,
      listing_city,
      listing_image,
      message
    } = req.body;

    if (!landlord_id) {
      const listingRes = await pool.query(
        'SELECT landlord_id FROM listings WHERE id = $1',
        [listing_id]
      );

      if (listingRes.rows.length > 0) {
        landlord_id = listingRes.rows[0].landlord_id;
      }
    }

    if (!landlord_id) {
      landlord_id = 1;
    }

    let inquiryRes = await pool.query(
      `SELECT id
       FROM inquiries
       WHERE listing_id = $1
       AND renter_id = $2`,
      [
        listing_id,
        renter_id || null
      ]
    );

    let inquiryId;

    if (inquiryRes.rows.length > 0) {
      inquiryId = inquiryRes.rows[0].id;
    } else {
      const newInquiry = await pool.query(
        `INSERT INTO inquiries (
          listing_id,
          renter_id,
          landlord_id,
          renter_name,
          renter_email,
          renter_phone,
          listing_title,
          listing_price,
          listing_city,
          listing_image,
          message
        )
        VALUES (
          $1, $2, $3, $4, $5, $6,
          $7, $8, $9, $10, $11
        )
        RETURNING id`,
        [
          listing_id,
          renter_id || null,
          landlord_id,
          renter_name || 'Prospective Tenant',
          renter_email || null,
          renter_phone || null,
          listing_title || 'Rental Property',
          listing_price || 0,
          listing_city || 'Metro Manila',
          listing_image || null,
          message
        ]
      );

      inquiryId = newInquiry.rows[0].id;
    }

    await pool.query(
      `INSERT INTO messages (
        inquiry_id,
        sender_role,
        sender_name,
        message_text
      )
      VALUES ($1, 'renter', $2, $3)`,
      [
        inquiryId,
        renter_name || 'Renter',
        message
      ]
    );

    res.json({
      message: 'Inquiry submitted successfully!',
      inquiry_id: inquiryId
    });
  } catch (err) {
    console.error("❌ INQUIRY ERROR:", err.message);

    res.status(500).json({
      message: 'Failed to send inquiry: ' + err.message
    });
  }
});

// GET: Fetch conversations for renter
app.get('/api/inquiries/renter/:renterId', async (req, res) => {
  try {
    const { renterId } = req.params;

    const result = await pool.query(
      `SELECT
        i.id,
        i.listing_id,
        i.renter_id,
        i.landlord_id,
        i.created_at,
        COALESCE(
          u.full_name,
          i.renter_name,
          'Prospective Tenant'
        ) AS renter_name,
        COALESCE(
          u.email,
          i.renter_email,
          'No email provided'
        ) AS renter_email,
        COALESCE(
          u.phone_number,
          i.renter_phone,
          'No phone provided'
        ) AS renter_phone,
        COALESCE(
          l.title,
          i.listing_title,
          'Rental Unit'
        ) AS listing_title,
        COALESCE(
          l.monthly_rent,
          i.listing_price,
          0
        ) AS listing_price,
        COALESCE(
          l.city,
          i.listing_city,
          'Metro Manila'
        ) AS listing_city,
        COALESCE(
          l.image_url,
          i.listing_image
        ) AS listing_image,
        COALESCE(
          l.property_type,
          'Rental'
        ) AS property_type,
        (
          SELECT message_text
          FROM messages
          WHERE inquiry_id = i.id
          ORDER BY created_at DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT created_at
          FROM messages
          WHERE inquiry_id = i.id
          ORDER BY created_at DESC
          LIMIT 1
        ) AS last_updated
       FROM inquiries i
       LEFT JOIN listings l
         ON i.listing_id = l.id
       LEFT JOIN users u
         ON i.renter_id = u.id
       WHERE i.renter_id = $1
       ORDER BY last_updated DESC`,
      [renterId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(
      "❌ FETCH RENTER INQUIRIES ERROR:",
      err.message
    );

    res.status(500).json({
      message: 'Failed to fetch renter inquiries'
    });
  }
});

// GET: Fetch conversations for landlord
app.get('/api/inquiries/landlord/:landlordId', async (req, res) => {
  try {
    const { landlordId } = req.params;

    const result = await pool.query(
      `SELECT
        i.id,
        i.listing_id,
        i.renter_id,
        i.landlord_id,
        i.created_at,
        COALESCE(
          u.full_name,
          i.renter_name,
          'Prospective Tenant'
        ) AS renter_name,
        COALESCE(
          u.email,
          i.renter_email,
          'No email provided'
        ) AS renter_email,
        COALESCE(
          u.phone_number,
          i.renter_phone,
          'No phone provided'
        ) AS renter_phone,
        COALESCE(
          l.title,
          i.listing_title,
          'Rental Unit'
        ) AS listing_title,
        COALESCE(
          l.monthly_rent,
          i.listing_price,
          0
        ) AS listing_price,
        COALESCE(
          l.city,
          i.listing_city,
          'Metro Manila'
        ) AS listing_city,
        COALESCE(
          l.image_url,
          i.listing_image
        ) AS listing_image,
        COALESCE(
          l.property_type,
          'Rental'
        ) AS property_type,
        (
          SELECT message_text
          FROM messages
          WHERE inquiry_id = i.id
          ORDER BY created_at DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT created_at
          FROM messages
          WHERE inquiry_id = i.id
          ORDER BY created_at DESC
          LIMIT 1
        ) AS last_updated
       FROM inquiries i
       LEFT JOIN listings l
         ON i.listing_id = l.id
       LEFT JOIN users u
         ON i.renter_id = u.id
       WHERE i.landlord_id = $1
       ORDER BY last_updated DESC`,
      [landlordId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(
      "❌ FETCH INQUIRIES ERROR:",
      err.message
    );

    res.status(500).json({
      message: 'Failed to fetch conversations'
    });
  }
});

// GET: Fetch message history
app.get('/api/inquiries/:inquiryId/messages', async (req, res) => {
  try {
    const { inquiryId } = req.params;

    const result = await pool.query(
      `SELECT *
       FROM messages
       WHERE inquiry_id = $1
       ORDER BY created_at ASC`,
      [inquiryId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(
      "❌ FETCH MESSAGES ERROR:",
      err.message
    );

    res.status(500).json({
      message: 'Failed to fetch thread messages'
    });
  }
});

// POST: Send reply
app.post('/api/inquiries/:inquiryId/messages', async (req, res) => {
  try {
    const { inquiryId } = req.params;

    const {
      sender_role,
      sender_name,
      message_text
    } = req.body;

    const newMsg = await pool.query(
      `INSERT INTO messages (
        inquiry_id,
        sender_role,
        sender_name,
        message_text
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *`,
      [
        inquiryId,
        sender_role || 'landlord',
        sender_name || 'Landlord',
        message_text
      ]
    );

    res.json({
      message: 'Message sent successfully!',
      messageData: newMsg.rows[0]
    });
  } catch (err) {
    console.error(
      "❌ SEND MESSAGE ERROR:",
      err.message
    );

    res.status(500).json({
      message: 'Failed to send reply'
    });
  }
});

app.listen(port, () => {
  console.log(
    `Roomie Rent backend server running on port ${port}`
  );
});

// Global Safety Handlers to prevent unexpected server crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Promise Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception thrown:', error);
  // Optional: Perform any necessary cleanups here before exiting if critical
});