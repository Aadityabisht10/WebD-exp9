const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    email: {
        type: String,
        unique: true
    },
    password: String
});

const User = mongoose.model("User", userSchema);

// Register User
app.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).send("All fields are required");
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).send("Email already registered");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        res.status(201).send("User registered successfully");

    } catch (error) {
        res.status(500).send("Registration failed");
    }
});

// Login User
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send("User not found");
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(400).send("Invalid password");
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token: token
        });

    } catch (error) {
        res.status(500).send("Login failed");
    }
});

// Authentication Middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send("Access denied");
    }

    const token = authHeader.split(" ")[1];

    try {
        const verified = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = verified;
        next();

    } catch (error) {
        res.status(401).send("Invalid or expired token");
    }
}

// Protected Profile Route
app.get("/profile", verifyToken, async (req, res) => {
    const user = await User.findById(req.user.id)
        .select("-password");

    if (!user) {
        return res.status(404).send("User not found");
    }

    res.json(user);
});

// Start Server
app.listen(process.env.PORT, () => {
    console.log(
        "Server running at http://localhost:" + process.env.PORT
    );
});