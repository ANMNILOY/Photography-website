const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const validator = require('validator');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const passport = require('passport');
const passportLocal = require('passport-local').Strategy;
const passportJwt = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// for MongoDB connection
mongoose.connect('mongodb://localhost:27017/photography-website', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// Passport initialization
app.use(passport.initialize());

// Local strategy
passport.use(
  new passportLocal({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return done(null, false, { message: 'Invalid credentials' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

// JWT strategy
passport.use(
  new passportJwt(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secret-key',
    },
    async (payload, done) => {
      try {
        const user = await User.findById(payload.userId);
        if (!user) {
          return done(null, false, { message: 'User not found' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Google OAuth strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: 'client-id',
      clientSecret: 'client-secret',
      callbackURL: 'http://website.com/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let user = await User.findOne({ email });

        if (!user) {
          // Creating a new user if not found
          user = new User({ email });
          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Facebook OAuth strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: 'facebook-app-id',
      clientSecret: 'facebook-app-secret',
      callbackURL: 'http://website.com/auth/facebook/callback',
      profileFields: ['id', 'emails', 'name'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let user = await User.findOne({ email });

        if (!user) {
          // Create a new user if not found
          user = new User({ email });
          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

app.use(passport.initialize());

// Register route
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate email
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  // Validate password
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, 'secret-key', { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user route
app.get('/api/user/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user route
app.put('/api/user/:userId', async (req, res) => {
  const userId = req.params.userId;
  const { picture, bio } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 'profile.picture': picture, 'profile.bio': bio },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: updatedUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Forgot password route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a password reset token
    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // Token valid for 1 hour
    await user.save();

    // Send email with reset link
    const resetLink = `http://website.com/reset-password/${token}`;
    const mailOptions = {
      from: 'email@gmail.com', // Replace with your email
      to: email,
      subject: 'Password Reset',
      text: `Click the following link to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
