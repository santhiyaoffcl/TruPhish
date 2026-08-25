const mongoose = require('mongoose');

const mongoURI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/truphish';

console.log('🔍 Connecting to MongoDB...');

mongoose
  .connect(mongoURI, {
    dbName: 'truphish',
    serverSelectionTimeoutMS: 10000
  })
  .then(() => console.log('✅ Connected to MongoDB successfully.'))
  .catch((err) => console.error('❌ MongoDB Connection Failed:', err.message));

module.exports = mongoose.connection;
