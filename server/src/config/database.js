require('dotenv').config();
const mongoose = require('mongoose');
const config = require('./environment');

//mongoDB connection function
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(config.MONGODB_URI, {
            maxPoolSize: 10, //maintain up to 10 socket connections
            serverSelectionTimeoutMS: 5000, //keep trying to send operations for 5 seconds
            socketTimeoutMS: 45000, //close sockets after 45 seconds of inactivity
            // bufferMaxEntries: 0, // dsable mongoose buffering
            // bufferCommands: false, //disable mongoose buffering
        });

        console.log(`MongoDB Connected: ${conn.connection.host}`);
        
        //handle connection events
        mongoose.connection.on('error', (err) => {
            console.error('MongoDB connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            console.log('MongoDB disconnected');
        });

        //graceful shutdown
        process.on('SIGINT', async () => {
            await mongoose.connection.close();
            console.log('MongoDB connection closed through app termination');
            process.exit(0);
        });

    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
};

module.exports = { connectDB, mongoose };