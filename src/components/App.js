// src/components/Profile.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';

const Profile = () => {
  const [user, setUser] = useState({});
  const [picture, setPicture] = useState('');
  const [bio, setBio] = useState('');

  useEffect(() => {
    // Fetch user profile data when the component mounts
    const fetchProfile = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/user/your-user-id'); // Replace with actual user ID
        setUser(response.data.user);
        setPicture(response.data.user.profile.picture);
        setBio(response.data.user.profile.bio);
      } catch (error) {
        console.error(error.response.data);
      }
    };

    fetchProfile();
  }, []);

  const handleUpdateProfile = async () => {
    try {
      const response = await axios.put('http://localhost:5000/api/user/your-user-id', {
        picture,
        bio,
      }); // Replace with actual user ID
      console.log(response.data);
    } catch (error) {
      console.error(error.response.data);
    }
  };

  return (
    <div>
      <h2>Profile</h2>
      <img src={`http://localhost:5000/images/${picture}`} alt="Profile" />
      <input type="text" placeholder="Bio" value={bio} onChange={(e) => setBio(e.target.value)} />
      <input type="file" onChange={(e) => setPicture(e.target.files[0])} />
      <button onClick={handleUpdateProfile}>Update Profile</button>
    </div>
  );
};

export default Profile;
