import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            photo: req.body.photo
        });

        await newUser.save();

        res.status(200).json({ success: true, message: "Successfully created" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the user exists
        const existingUser = await User.findOne({ email });
        if (!existingUser) return res.status(404).json({ message: "User doesn't exist" });

        // Check if the password is correct
        const isPasswordCorrect = bcrypt.compare(password, existingUser.password);
        if (!isPasswordCorrect) return res.status(400).json({ message: "Invalid credentials" });

        // Generate a token
        const token = jwt.sign({ email: existingUser.email, role:existingUser.role, id: existingUser._id }, 'JWT-SECRET_KEY', { expiresIn: '1' });

        // Send the user and token as a response
        res.status(200).json({ result: existingUser, token });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};