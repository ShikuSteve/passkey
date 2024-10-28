import express, { NextFunction, Request, Response } from "express";
import session, { SessionData } from "express-session";
import mongoose from "mongoose";
import { User } from "./models/User.js";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { Credentials } from "./models/Credential.js";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
  AuthenticatorTransportFuture,
  WebAuthnCredential,
} from "@simplewebauthn/types";

const app = express();
app.use(express.json());

mongoose.connect("mongodb://localhost:27017/passkey", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as mongoose.ConnectOptions);

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
app.get("/users", async (res: Response) => {
  try {
    const users = await User.find(); // Fetch all users
    res.status(200).json(users); // Send users as JSON response
  } catch (error) {
    res.status(500).json({ error: "An error occurred while fetching users." });
  }
});

//---------------------------User Registration-------------------------------------//

// Signup Route
app.post("/signup", async (req: Request, res: Response, next: NextFunction) => {
  try {
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
  } catch (error) {
    next(error); // Pass any errors to the next middleware
  }
});
// 1. Generate Credential Creation Options
app.post("/registerRequest", async (req: Request, res: Response) => {
  const { userId } = req.body;
  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  try {
    const excludeCredentials: Array<{
      id: string;
      type: string;
      transports?: AuthenticatorTransportFuture[];
    }> = [];

    // Get existing credentials for exclusion
    const credential = await Credentials.find({ userId: user._id });
    console.log("Fetched credentials:", credential);

    if (credential.length > 0) {
      for (const cred of credential) {
        excludeCredentials.push({
          id: isoBase64URL.fromBuffer(isoBase64URL.toBuffer(cred.credentialId)),
          type: "public-key",
          transports: cred.transports as AuthenticatorTransportFuture[],
        });
      }
    }

    const rpID = "localhost"; // Ensure this is defined
    console.log("rpId before generating options:", rpID);

    // Generate registration options for WebAuthn create
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
  } catch (error: any) {
    console.log(error);
    return res.status(400).send({ error: error.message });
  }
});

app.post("/registerResponse", async (req, res) => {
  const { response, userId } = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = `${req.protocol}://${req.get("host")}`;
  const expectedRPID = "localhost";

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
      // requireUserVerification: false,
    });

    if (!verified) {
      return res.status(400).send({ error: "Authentication failed" });
    }

    // Save the credential to the database

    if (!registrationInfo) {
      return res
        .status(400)
        .json({ error: "Registration information is missing." });
    }
    const credentialID = response.credential.id;
    const credentialPublicKey = response.credential.publicKey;
    const credentialBackedUp = registrationInfo.credentialBackedUp;

    await Credentials.create({
      userId,
      credentialId: isoBase64URL.fromBuffer(credentialID),
      publicKey: isoBase64URL.fromBuffer(credentialPublicKey),
      transports: response.transports || [],
      backed_up: credentialBackedUp || false,
      name: req.useragent?.platform || "default",
    });

    // Kill the challenge for this session.
    delete req.session.challenge;
    req.session.username = user.userName;
    req.session.signedIn = true;

    return res.json(user);
  } catch (error: any) {
    delete req.session.challenge;
    console.log(error);
    return res.status(400).json({ error: error.message });
  }
});

//-------------------------------User Authentication---------------------------------------

app.post(
  "/signinRequest",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authenticationOptions = await generateAuthenticationOptions({
        rpID: "localhost",
        allowCredentials: [],
      });
      // Save the challenge in the user session
      req.session.challenge = authenticationOptions.challenge;
      return res.json(authenticationOptions);
    } catch (error: any) {
      console.log(error);
      return res.status(400).json({ error: error.message });
    }
  }
);

app.post(
  "/signinResponse",
  async (req: Request, res: Response, next: NextFunction) => {
    const { response, userId } = req.body;
    const expectedChallenge = req.session.challenge;
    const expectedRPID = "localhost";
    const expectedOrigin = `${req.protocol}://${req.get("host")}`;

    try {
      const credential = await Credentials.findById(response.id);
      if (!credential) {
        return res.status(400).json({ error: "Invalid credential id" });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }
      if (expectedChallenge === undefined) {
        return res
          .status(400)
          .json({ error: "Expected challenge is missing from session." });
      }

      const webAuthnCredential = {
        credentialPublicKey: isoBase64URL.toBuffer(
          response.credential.publicKey
        ),
        credentialID: isoBase64URL.toBuffer(response.credential.id),
        transports: response.credential.transports,
      };

      const verificationCredentials: WebAuthnCredential = {
        id: isoBase64URL.fromBuffer(webAuthnCredential.credentialID),
        publicKey: webAuthnCredential.credentialPublicKey,
        counter: response.credential.counter,
      };

      const { verified } = await verifyAuthenticationResponse({
        response,
        credential: verificationCredentials,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        requireUserVerification: false,
      });
      if (!verified) {
        return res.status(400).json({ error: "Authentication failed" });
      }
      delete req.session.challenge;
      req.session.username = user.userName;
      req.session.signedIn = true;

      return res.json(user);
    } catch (error: any) {
      delete req.session.challenge;
      console.log(error);
      return res.status(400).json({ error: error.message });
    }
  }
);

app.get("/credential", async (req: Request, res: Response) => {
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

    // Check if credentials exist
    if (!credentials || credentials.length === 0) {
      return res
        .status(404)
        .json({ error: "No credentials found for this user" });
    }

    // Return the credentials
    return res.json(credentials);
  } catch (error) {
    console.error("Error retrieving credentials:", error);
    return res
      .status(500)
      .json({ error: "An error occurred while retrieving credentials" });
  }
});

// Server start
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
