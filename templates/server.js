const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const User = require('./User');

const app = express();
app.use(express.static(__dirname));
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.connect('mongodb+srv://l211763:mohsin123@cluster0.2wthpzf.mongodb.net/FYP?retryWrites=true&w=majority');

// Check connection
const db = mongoose.connection;
db.once('open', () => {
    console.log("MongoDB connection is successful");
});

// Serve HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Login&Signup.html'));
});

// Handle signup form submission
app.post('/signup', async (req, res) => {
    const { email, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        return res.json({ success: false, message: 'Passwords do not match' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.json({ success: false, message: 'User already exists with this email' });
        }

        const userId = uuidv4();
        const user = new User({ userId, email, password });
        await user.save();
        res.json({ success: true, message: `User registered successfully with User ID: ${userId}` });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: 'Error registering user' });
    }
});


// Handle login form submission

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            // If user does not exist
            return res.json({ success: false, message: 'Incorrect Email ID' });
        } else if (user.password !== password) {
            // If password is incorrect
            return res.json({ success: false, message: 'Incorrect Password' });
        } else {
            // If email and password match
            return res.json({ success: true, redirectUrl: `http://127.0.0.1:5000?userId=${user.userId}` });
        }
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: 'Error logging in' });
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
