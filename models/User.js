// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  profile: {
    picture: {
      type: String,
      default: 'default-profile-picture.jpg', // Add a default profile picture file
    },
    bio: {
      type: String,
      default: '',
    },
  },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
