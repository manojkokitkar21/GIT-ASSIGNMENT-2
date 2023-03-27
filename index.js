const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost/assignment', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: {
        type: String,
        unique: true
    },
    password: String
});

// Post Schema
const postSchema = new mongoose.Schema({
    title: String,
    body: String,
    image: String,
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
});

// User Model
const User = mongoose.model('User', userSchema);

// Post Model
const Post = mongoose.model('Post', postSchema);

// Middleware to parse request body
app.use(bodyParser.json());

// Register API
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        res.sendStatus(201);
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }
});

// Login API
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });

        // Check if user exists
        if (!user) {
            return res.sendStatus(401);
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.sendStatus(401);
        }

        // Create and sign JWT
        const token = jwt.sign({ userId: user._id }, 'secret');

        res.json({ token });
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }
});

// Middleware for authentication and authorization
const auth = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(' ')[1];

        // Verify JWT
        const decodedToken = jwt.verify(token, 'secret');

        // Add user id to request object
        req.userId = decodedToken.userId;

        next();
    } catch (err) {
        console.log(err);
        res.sendStatus(401);
    }
};

// Get all posts API
app.get('/posts', auth, async (req, res) => {
    try {
        // Get all posts with user info
        const posts = await Post.find().populate('user', 'name email');

        res.json({ posts });
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }
});

