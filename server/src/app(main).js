const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const routes = require("./routes");
const { connectDB } = require('./config/database');

const app = express();

//middleware
app.use(cookieParser());
app.use(express.json());

app.use(
    cors({
        origin: ["http://localhost:5173", "http://localhost:8000"],
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
    })
);

//connect to mongoDB
connectDB();


//routes
app.use('/api', routes);


module.exports = app;