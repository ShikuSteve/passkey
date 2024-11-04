import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import { User } from "./models/User.js";
import { isoUint8Array } from "@simplewebauthn/server/helpers";
import { Credentials } from "./models/Credential.js";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, } from "@simplewebauthn/server";
import { AuthOptions } from "./models/AuthOptions.js";
const app = express();
app.use(express.json());
dotenv.config();
const uri = process.env.MONGODB_URI;
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "http://localhost:3001");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    next();
});
app.get("/users", async (req, res, next) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    }
    catch (error) {
        res.status(500).json({ error: "An error occurred while fetching users." });
    }
});
app.post("/signup", async (req, res, next) => {
    try {
        const { email, userName } = req.body;
        if (!email || !userName) {
            return res
                .status(400)
                .json({ error: "Both email and userName are required" });
        }
        let user = await User.findOne({ email });
        if (user) {
            return res.status(200).json({
                message: "Login successful",
                user,
            });
        }
        user = new User({ email, userName });
        await user.save();
        res.status(201).json({
            message: "User created successfully",
            user,
        });
    }
    catch (error) {
        next(error);
    }
});
app.post("/registerRequest", async (req, res) => {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    const exitingAuthOptions = await AuthOptions.findOne({
        userClientId: userId,
    });
    if (exitingAuthOptions) {
        await AuthOptions.deleteOne({ userClientId: userId });
        console.log(`Deleted existing AuthOptions for userId: ${userId}`);
    }
    try {
        const excludeCredentials = [];
        const credential = await Credentials.find({ userId: user._id });
        if (credential.length > 0) {
            for (const cred of credential) {
                excludeCredentials.push({
                    id: cred.credentialId,
                    type: "public-key",
                    transports: cred.transports,
                });
            }
        }
        const rpID = "localhost";
        const registrationOptions = await generateRegistrationOptions({
            rpName: "PassKey",
            rpID,
            userID: isoUint8Array.fromUTF8String(user._id.toString()),
            userName: user.email,
            userDisplayName: user.userName,
            excludeCredentials,
            attestationType: "none",
            authenticatorSelection: {
                authenticatorAttachment: "platform",
                requireResidentKey: true,
                userVerification: "required",
            },
            supportedAlgorithmIDs: [-7, -257],
        });
        console.log(registrationOptions, "yoh😀😀😀😀😀😀");
        await AuthOptions.create({
            challenge: registrationOptions.challenge,
            userId: registrationOptions.user.id,
            timeout: registrationOptions.timeout,
            userClientId: user._id,
        });
        return res.json(registrationOptions);
    }
    catch (error) {
        console.log(error);
        return res.status(400).send({ error: error.message });
    }
});
app.post("/registerResponse", async (req, res) => {
    const { response, userId } = req.body;
    const exitingAuthOptions = await AuthOptions.findOne({
        userClientId: userId,
    });
    if (!exitingAuthOptions) {
        return res.status(400).json({ error: "No Auth Options for the user" });
    }
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    const expectedChallenge = exitingAuthOptions.challenge;
    const expectedOrigin = req.get("origin") || `${req.protocol}://${req.get("host")}`;
    const expectedRPID = "localhost";
    console.log(response);
    console.log("Request headers:", req.headers);
    console.log("Session challenge:", exitingAuthOptions.challenge);
    if (!expectedChallenge) {
        return res
            .status(400)
            .json({ error: "Challenge is missing from session." });
    }
    if (!response) {
        return res.status(400).json({ error: "No response found" });
    }
    try {
        const { verified, registrationInfo } = await verifyRegistrationResponse({
            response,
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
            requireUserVerification: true,
        });
        if (!verified) {
            return res.status(400).send({ error: "Authentication failed" });
        }
        if (!registrationInfo) {
            return res
                .status(400)
                .json({ error: "Registration information is missing." });
        }
        const { credential, credentialBackedUp } = registrationInfo;
        console.log(registrationInfo);
        const publicKeyBuffer = Buffer.from(credential.publicKey);
        await Credentials.create({
            userId,
            credentialId: credential.id,
            counter: credential.counter || 0,
            publicKey: publicKeyBuffer,
            transports: credential.transports,
            backed_up: credentialBackedUp || false,
            name: req.useragent?.platform || "default",
        });
        await AuthOptions.deleteOne({ userClientId: userId });
        return res.json(user);
    }
    catch (error) {
        await AuthOptions.deleteOne({ userClientId: userId });
        console.log(error);
        return res.status(400).json({ error: error.message });
    }
});
app.post("/signinRequest", async (req, res, next) => {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    const exitingAuthOptions = await AuthOptions.findOne({
        userClientId: userId,
    });
    if (exitingAuthOptions) {
        await AuthOptions.deleteOne({ userClientId: userId });
        console.log(`Deleted existing AuthOptions for userId: ${userId}`);
    }
    try {
        const authenticationOptions = await generateAuthenticationOptions({
            rpID: "localhost",
            allowCredentials: [],
        });
        console.log("Session Challenge after setting:", req.session.challenge);
        await AuthOptions.create({
            challenge: authenticationOptions.challenge,
            userId: user._id,
            timeout: authenticationOptions.timeout,
            userClientId: user._id,
        });
        return res.json(authenticationOptions);
    }
    catch (error) {
        console.log(error);
        return res.status(400).json({ error: error.message });
    }
});
app.post("/signinResponse", async (req, res, next) => {
    const { response, userId } = req.body;
    console.log(response, userId);
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    const exitingAuthOptions = await AuthOptions.findOne({
        userClientId: userId,
    });
    if (!exitingAuthOptions) {
        return res.status(400).json({ error: "No Auth Options for the user" });
    }
    const expectedChallenge = exitingAuthOptions.challenge;
    const expectedRPID = "localhost";
    const expectedOrigin = req.get("origin") || `${req.protocol}://${req.get("host")}`;
    if (!expectedChallenge) {
        return res.status(400).json({ error: "Missing challenge from session." });
    }
    const exitingCredential = await Credentials.findOne({
        credentialId: response.id,
    });
    if (!exitingCredential)
        return res.status(400).json({ error: "Invalid credential id" });
    console.log(exitingCredential, "--------------------------------------------yah-------------------------------", exitingCredential.id);
    try {
        const publicKeyBuffer = exitingCredential.publicKey;
        const publicKeyUint8Array = new Uint8Array(publicKeyBuffer);
        const { verified } = await verifyAuthenticationResponse({
            response,
            credential: {
                id: exitingCredential.id,
                publicKey: publicKeyUint8Array,
                counter: exitingCredential.counter || 0,
                transports: exitingCredential.transports,
            },
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
        });
        if (!verified) {
            return res.status(400).json({ error: "Authentication failed" });
        }
        await AuthOptions.deleteOne({ userClientId: userId });
        console.log("Updated Session Data:", req.session);
        return res.json(user);
    }
    catch (error) {
        await AuthOptions.deleteOne({ userClientId: userId });
        console.error("Error during signinResponse:", error);
        return res.status(500).json({ error: error.message });
    }
});
app.get("/credential", async (req, res) => {
    const { userId } = req.query;
    if (!userId) {
        return res.status(400).json({ error: "User ID is required" });
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const credentials = await Credentials.find({ userId: userId });
        if (!credentials || credentials.length === 0) {
            return res
                .status(404)
                .json({ error: "No credentials found for this user" });
        }
        return res.json(credentials);
    }
    catch (error) {
        console.error("Error retrieving credentials:", error);
        return res
            .status(500)
            .json({ error: "An error occurred while retrieving credentials" });
    }
});
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
