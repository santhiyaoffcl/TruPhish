const express = require('express');
const cors = require('cors');
require('dotenv').config();
require('./config/db');

const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const chatRoutes = require('./routes/chatRoutes');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/chat', chatRoutes);

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 5000;

app.get("/", (req,res)=>{
    res.send("server is running")
})

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
