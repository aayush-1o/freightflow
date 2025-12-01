require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());

// ENV
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME;
const port = process.env.PORT || 5000;

let db;

// CONNECT DB
async function connectDB() {
    try {
        const client = new MongoClient(uri);
        await client.connect();
        db = client.db(dbName);
        console.log(`✅ Connected to DB: ${dbName}`);
    } catch (err) {
        console.error("❌ MongoDB Error:", err);
        process.exit(1);
    }
}

// ===============================
// 1️⃣ USER REGISTRATION
// ===============================
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, phone, password, role } = req.body;

        if (!name || !email || !password)
            return res.status(400).json({ message: "Missing fields" });

        const users = db.collection("users");

        // check if exists
        const existing = await users.findOne({ email });
        if (existing)
            return res.status(409).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await users.insertOne({
            name,
            email,
            phone,
            password: hashedPassword,
            role,
            createdAt: new Date()
        });

        res.status(201).json({ message: "User created" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ===============================
// 2️⃣ USER LOGIN
// ===============================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const users = db.collection("users");
        const user = await users.findOne({ email });

        if (!user)
            return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).json({ message: "Invalid password" });

        res.json({
            message: "Login successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ===============================
// 3️⃣ FORGOT PASSWORD — Send Email
// ===============================
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const users = db.collection("users");
        const user = await users.findOne({ email });

        if (!user)
            return res.status(404).json({ message: "No account with this email" });

        // Create token
        const token = crypto.randomBytes(32).toString("hex");
        const expireTime = Date.now() + 10 * 60 * 1000; // 10 min

        await users.updateOne(
            { email },
            { $set: { resetToken: token, resetTokenExpires: expireTime } }
        );

        // Send email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const resetLink = `http://localhost:5500/pages/reset-password.html?token=${token}`;

        await transporter.sendMail({
            from: "FreightFlow Support",
            to: email,
            subject: "Reset Your Password",
            html: `
                <h2>Password Reset Request</h2>
                <p>Click the link below to reset your password:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>This link is valid for 10 minutes.</p>
            `
        });

        res.json({ message: "Reset link sent to email" });

    } catch (err) {
        console.error("Forgot Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// ===============================
// 4️⃣ VERIFY TOKEN
// ===============================
app.post('/api/verify-token', async (req, res) => {
    try {
        const { token } = req.body;
        const users = db.collection("users");

        const user = await users.findOne({
            resetToken: token,
            resetTokenExpires: { $gt: Date.now() }
        });

        if (!user)
            return res.status(400).json({ message: "Invalid or expired token" });

        res.json({ message: "Token valid" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ===============================
// 5️⃣ RESET PASSWORD
// ===============================
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        const users = db.collection("users");

        const user = await users.findOne({
            resetToken: token,
            resetTokenExpires: { $gt: Date.now() }
        });

        if (!user)
            return res.status(400).json({ message: "Invalid or expired token" });

        const hashed = await bcrypt.hash(newPassword, 10);

        await users.updateOne(
            { _id: user._id },
            {
                $set: { password: hashed },
                $unset: { resetToken: "", resetTokenExpires: "" }
            }
        );

        res.json({ message: "Password reset successfully" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// START
connectDB().then(() => {
    app.listen(port, () =>
        console.log(`🚀 Server running: http://localhost:${port}`)
    );
});
