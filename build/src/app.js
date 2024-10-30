import express from "express";
import session from "express-session";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";
import { User } from "./models/User.js";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { Credentials } from "./models/Credential.js";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, } from "@simplewebauthn/server";
const app = express();
app.use(express.json());
app.use(session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: "mongodb://localhost:27017/passkey",
        collectionName: "sessions",
        ttl: 14 * 24 * 60 * 60,
    }),
    cookie: {
        secure: false,
        maxAge: 14 * 24 * 60 * 60 * 1000,
        sameSite: "lax",
    },
}));
mongoose.connect("mongodb://localhost:27017/passkey", {
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
            return res.status(400).json({ error: "All fields are required" });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "User  already exists" });
        }
        const newUser = new User({ email, userName });
        await newUser.save();
        res
            .status(201)
            .json({ message: "User  created successfully", userId: newUser._id });
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
    try {
        const excludeCredentials = [];
        const credential = await Credentials.find({ userId: user._id });
        if (credential.length > 0) {
            for (const cred of credential) {
                excludeCredentials.push({
                    id: isoBase64URL.fromBuffer(isoBase64URL.toBuffer(cred.credentialId)),
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
                authenticatorAttachment: "cross-platform",
                requireResidentKey: true,
                userVerification: "preferred",
            },
            supportedAlgorithmIDs: [-7, -257],
        });
        req.session.challenge = registrationOptions.challenge;
        console.log(req.session);
        console.log(req.session.challenge);
        console.log(registrationOptions);
        return res.json(registrationOptions);
    }
    catch (error) {
        console.log(error);
        return res.status(400).send({ error: error.message });
    }
});
app.post("/registerResponse", async (req, res) => {
    const { response, userId } = req.body;
    const expectedChallenge = req.session.challenge;
    const expectedOrigin = req.get("origin") || `${req.protocol}://${req.get("host")}`;
    const expectedRPID = "localhost";
    console.log(response);
    console.log("Request headers:", req.headers);
    console.log("Session in /registerResponse:", req.session);
    console.log("Session challenge:", req.session.challenge);
    if (!expectedChallenge) {
        return res
            .status(400)
            .json({ error: "Challenge is missing from session." });
    }
    if (!req.session.challenge) {
        console.log("Challenge is missing from session.");
        return res.status(400).json({ error: "Challenge not found in session." });
    }
    if (!response) {
        return res.status(400).json({ error: "No response found" });
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        if (typeof expectedChallenge !== "string") {
            return res.status(400).json({ error: "Challenge not found in session." });
        }
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
        const credentialID = response.id;
        const credentialPublicKey = response.credentialPublicKey;
        console.log("Credential ID:", credentialID);
        console.log("Public Key:", credentialPublicKey);
        if (!credentialID || !credentialPublicKey) {
            throw new Error("Credential ID or Public Key is missing.");
        }
        const credentialBackedUp = registrationInfo.credentialBackedUp;
        await Credentials.create({
            userId,
            credentialId: credentialID,
            publicKey: credentialPublicKey,
            transports: response.transports || [],
            backed_up: credentialBackedUp || false,
            name: req.useragent?.platform || "default",
        });
        delete req.session.challenge;
        req.session.username = user.userName;
        req.session.signedIn = true;
        return res.json(user);
    }
    catch (error) {
        delete req.session.challenge;
        console.log(error);
        return res.status(400).json({ error: error.message });
    }
});
app.post("/signinRequest", async (req, res, next) => {
    try {
        const authenticationOptions = await generateAuthenticationOptions({
            rpID: "localhost",
            allowCredentials: [],
        });
        console.log("Generated Challenge:", authenticationOptions.challenge);
        req.session.challenge = authenticationOptions.challenge;
        console.log("Session in signinRequest:", req.session);
        console.log("Session ID", req.sessionID);
        console.log("Session Challenge after setting:", req.session.challenge);
        return res.json(authenticationOptions);
    }
    catch (error) {
        console.log(error);
        return res.status(400).json({ error: error.message });
    }
});
app.post("/signinResponse", async (req, res, next) => {
    try {
        console.log("Session Data in signinResponse:", req.session);
        console.log("Session ID", req.sessionID);
        const { response, userId } = req.body;
        console.log(response);
        const expectedChallenge = req.session.challenge;
        console.log("Expected Challenge:", expectedChallenge);
        const expectedRPID = "localhost";
        const expectedOrigin = req.get("origin") || `${req.protocol}://${req.get("host")}`;
        if (!expectedChallenge) {
            return res
                .status(400)
                .json({ error: "Missing challenge from session." });
        }
        if (response.challenge === expectedChallenge) {
            console.error("Challenge mismatch!", response.challenge, expectedChallenge);
            return res.status(400).json({ error: "Invalid challenge." });
        }
        const credential = await Credentials.find({
            credentialId: response.id,
        });
        if (!credential)
            return res.status(400).json({ error: "Invalid credential id" });
        const user = await User.findById(userId);
        if (!user)
            return res.status(400).json({ error: "User  not found" });
        const verificationCredentials = {
            id: response.id,
            publicKey: response.publicKey,
            counter: response.counter,
            transports: response.transports,
        };
        const { verified } = await verifyAuthenticationResponse({
            response,
            credential: verificationCredentials,
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
        });
        if (!verified) {
            return res.status(400).json({ error: "Authentication failed" });
        }
        delete req.session.challenge;
        req.session.username = user.userName;
        req.session.signedIn = true;
        console.log("Updated Session Data:", req.session);
        return res.json(user);
    }
    catch (error) {
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
