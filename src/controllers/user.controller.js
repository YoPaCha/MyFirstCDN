const { users } = require("../models/data");

/*
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
*/

exports.getAllUsers = (req, res) => {
    try {
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users", error: error.message });
    }
};

exports.getUserById = (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        const user = users.find(u => u.id === userId);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: "Error fetching user", error: error.message });
    }
};

exports.createUser = (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check for duplicate email
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json({ message: "Email already in use" });
        }

        const newUser = {
            id: Date.now(),
            username,
            email,
            password,
            createdAt: new Date()
        };

        users.push(newUser);

        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ message: "Error creating user", error: error.message });
    }
};

exports.updateUser = (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { username, email, password } = req.body;

        const user = users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Update user fields if provided in the request body
        if (username) user.username = username;
        if (email) {
            // Check for duplicate email
            const emailInUse = users.find(u => u.email === email && u.id !== userId);
            if (emailInUse) {
                return res.status(409).json({ message: "Email already in use by another user" });
            }
            user.email = email;
        }
        if (password) user.password = password;  // Consider hashing if needed

        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: "Error updating user", error: error.message });
    }
};

exports.deleteUser = (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        const index = users.findIndex(u => u.id === userId);

        if (index === -1) {
            return res.status(404).json({ message: "User not found" });
        }

        users.splice(index, 1);

        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting user", error: error.message });
    }
};