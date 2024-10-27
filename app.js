import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import { User } from "./src/models/User.js";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { Credentials } from "./src/models/Credential.js";
import {
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const app = express();
app.use(express.json());

mongoose.connect("mongodb://localhost:27017/passkey", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);

// Signup Route
app.post("/signup", async (req, res) => {
  const { email, userName } = req.body;

  // Basic validation
  if (!email || !userName) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ error: "User  already exists" });
  }

  // Create new user
  const newUser = new User({ email, userName });
  await newUser.save();

  res
    .status(201)
    .json({ message: "User  created successfully", userId: newUser._id });
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find(); // Fetch all users
    res.status(200).json(users); // Send users as JSON response
  } catch (error) {
    res.status(500).json({ error: "An error occurred while fetching users." });
  }
});

// 1. Generate Credential Creation Options
app.post("/registerRequest", async (req, res) => {
  const { userId } = req.body;
  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  try {
    const excludeCredentials = [];

    // Get existing credentials for exclusion
    const credential = await Credentials.find({ userId: user._id });
    console.log("Fetched credentials:", credential);

    if (credential.length > 0) {
      for (const cred of credential) {
        excludeCredentials.push({
          id: isoBase64URL.toBuffer(cred.credentialId),
          type: "public-key",
          transports: cred.transports,
        });
      }
    }

    const rpId = "localhost"; // Ensure this is defined
    console.log("rpId before generating options:", rpId);

    // Generate registration options for WebAuthn create
    const registrationOptions = await generateRegistrationOptions({
      rpName: "PassKey",
      rpId,
      userID: isoUint8Array.fromUTF8String(user._id.toString()),
      userName: user.email,
      userDisplayName: user.userName,
      excludeCredentials,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
      },
      // Support for the two most common algorithms: ES256, and RS256
      supportedAlgorithmIDs: [-7, -257],
    });
    console.log("rpId:", registrationOptions.rp?.id);

    console.log("Registration options:", registrationOptions);

    req.session.challenge = registrationOptions.challenge;

    console.log("User  ID:", userId);
    console.log("User  found:", user);
    console.log("Existing credentials:", excludeCredentials);

    return res.json(registrationOptions);
  } catch (error) {
    console.log(error);
    return res.status(400).send({ error: error.message });
  }
});

//User Authentication

app.post("/registerResponse", async (req, res) => {
  const { response, userId } = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = `${req.protocol}://${req.get("host")}`;
  const expectedRPID = "localhost";

  try {
    const user = User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Find the credential stored to the database by the credential ID
    const credential = await Credentials.find({
      credentialId: response.credentialId,
    });
    console.log("Credential:", credential);

    if (!credential) {
      return res.status(400).send({ error: "Credential not found" });
    }

    // Base64URL decode some values
    const authenticator = {
      credentialPublicKey: isoBase64URL.toBuffer(cred.publicKey),
      credentialID: isoBase64URL.toBuffer(cred.id),
      transports: cred.transports,
    };

    console.log("Authenticator:", authenticator);
    // Verify the credential

    const { verified } = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
      requireUserVerification: false,
    });

    if (!verified) {
      return res.status(400).send({ error: "Authentication failed" });
    }
    // Kill the challenge for this session.
    delete req.session.challenge;
    req.session.username = user.username;
    req.session["signed-in"] = "yes";

    return res.json(user);
  } catch (error) {
    console.log(error);
    return res.status(400).send({ error: error.message });
  }
});

// Server start
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
