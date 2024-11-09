const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: 'http://qurandle.s3-website.us-east-2.amazonaws.com',
    credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// In-memory storage (replace with a database in production)
let users = [];

const SECRET_KEY = 'your_jwt_secret_key'; // Use a more secure key in production

app.get('/', (req, res) => {
    res.send('Qurandle backend is running');
});

app.use((req, res, next) => {
    console.log(`Received ${req.method} request for ${req.url}`);
    next();
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
    console.log('Login attempt for username:', req.body.username);
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        console.log('User not found:', username);
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Password mismatch for user:', username);
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
        console.log('Login successful for user:', username);
        res.json({ token, username });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.log('No auth header provided');
        return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.log('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

let leaderboard = {
    easy: [],
    medium: [],
    hard: []
};

// Update /submit-score endpoint
app.post('/submit-score', authenticateJWT, (req, res) => {
    const { score, level } = req.body;

    if (!score || !level) {
        return res.status(400).json({ message: 'Score and level must be provided' });
    }

    // Ensure the leaderboard structure has an array for this level
    if (!leaderboard[level]) {
        leaderboard[level] = [];
    }

    const leaderboardForLevel = leaderboard[level];
    const userIndex = leaderboardForLevel.findIndex(entry => entry.username === req.user.username);

    if (userIndex !== -1) {
        if (score > leaderboardForLevel[userIndex].score) {
            leaderboardForLevel[userIndex].score = score;
        }
    } else {
        leaderboardForLevel.push({ username: req.user.username, score });
    }

    // Sort and limit leaderboard to top 10
    leaderboardForLevel.sort((a, b) => b.score - a.score);
    leaderboard[level] = leaderboardForLevel.slice(0, 10);

    res.status(201).json({ message: 'Score submitted successfully' });
});



// Update /leaderboard endpoint to return specific level
app.get('/leaderboard', (req, res) => {
    const { level } = req.query;
    if (!leaderboard[level]) return res.status(400).json({ message: 'Invalid level' });
    res.json(leaderboard[level]);
});


// New endpoint to remove a score (for admin use)
app.post('/remove-score', authenticateJWT, (req, res) => {
    console.log('Passed authentication, processing request to remove score');
    try {
        const { username } = req.body;
        
        console.log('Attempting to remove score for username:', username);
        
        if (!username) {
            console.log('Username not provided in request body');
            return res.status(400).json({ message: 'Username is required' });
        }
        
        const initialLength = leaderboard.length;
        leaderboard = leaderboard.filter(entry => entry.username !== username);
        
        if (leaderboard.length < initialLength) {
            console.log('Score removed successfully for:', username);
            res.json({ message: 'Score removed successfully' });
        } else {
            console.log('User not found in leaderboard:', username);
            res.status(404).json({ message: 'User not found in leaderboard' });
        }
    } catch (error) {
        console.error('Error in /remove-score:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

app.use((req, res) => {
    console.log('Route not found:', req.url);
    res.status(404).json({ message: 'Endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});