import express, { NextFunction, Request, Response } from "express";
import session, { SessionData } from "express-session";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";
import dotenv from "dotenv";
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
dotenv.config();

const uri = process.env.MONGODB_URI as string;

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as mongoose.ConnectOptions);

app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://passkey-demos.onrender.com"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

// Session Middleware
app.use(
  session({
    secret: "keyboard cat", // Change this to a more secure secret in production
    resave: false,
    saveUninitialized: true, // This should be true for session creation
    store: MongoStore.create({
      mongoUrl: uri,
      collectionName: "sessions",
      ttl: 14 * 24 * 60 * 60, // 14 days
    }),
    cookie: {
      secure: true, // Set to true if using HTTPS
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days in milliseconds
      sameSite: "none", // 'lax' is a good default
    },
  })
);

app.get("/users", async (req: Request, res: Response, next: NextFunction) => {
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
    // console.log("Fetched credentials:", credential);

    if (credential.length > 0) {
      for (const cred of credential) {
        excludeCredentials.push({
          // id: isoBase64URL.fromBuffer(isoBase64URL.toBuffer(cred.credentialId)),
          id: cred.credentialId,
          type: "public-key",
          transports: cred.transports as AuthenticatorTransportFuture[],
        });
      }
    }

    const rpID = "passkey-demos.onrender.com"; // Ensure this is defined
    // console.log("rpId before generating options:", rpID);

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
        userVerification: "required",
      },
      // Support for the two most common algorithms: ES256, and RS256
      supportedAlgorithmIDs: [-7, -257],
    });

    req.session.challenge = registrationOptions.challenge;
    console.log(req.session);
    console.log(req.session.challenge);
    console.log(registrationOptions);

    // console.log("User  ID:", userId);
    // console.log("User  found:", user);
    // console.log("Existing credentials:", excludeCredentials);

    return res.json(registrationOptions);
  } catch (error: any) {
    console.log(error);
    return res.status(400).send({ error: error.message });
  }
});

app.post("/registerResponse", async (req: Request, res: Response) => {
  const { response, userId } = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin =
    req.get("origin") || `${req.protocol}://${req.get("host")}`;

  const expectedRPID = "passkey-demos.onrender.com";
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

    // Save the credential to the database

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
        rpID: "passkey-demos.onrender.com",
        allowCredentials: [],
      });
      // Save the challenge in the user session

      console.log("Generated Challenge:", authenticationOptions.challenge);

      req.session.challenge = authenticationOptions.challenge;

      console.log("Session in signinRequest:", req.session);
      console.log("Session ID", req.sessionID);

      console.log("Session Challenge after setting:", req.session.challenge);

      return res.json(authenticationOptions);
    } catch (error: any) {
      console.log(error);
      return res.status(400).json({ error: error.message });
    }
  }
);

// app.post(
//   "/signinResponse",
//   async (req: Request, res: Response, next: NextFunction) => {
//     console.log("Session Data in signinResponse:", req.session);

//     const { response, userId } = req.body;
//     console.log(response, "yyyyyyyyyyyyyyyyyyyyyyyyyyyyy");
//     const expectedChallenge = req.session.challenge;
//     console.log("Expected Challenge:", expectedChallenge);
//     const expectedRPID = "passkey-demos.onrender.com";
//     const expectedOrigin =
//       req.get("origin") || `${req.protocol}://${req.get("host")}`;

//     try {
//       const credential = await Credentials.findOne({
//         credentialId: response.id,
//       });
//       if (!credential) {
//         return res.status(400).json({ error: "Invalid credential id" });
//       }

//       const user = await User.findById(userId);
//       if (!user) {
//         return res.status(400).json({ error: "User not found" });
//       }
//       if (expectedChallenge === undefined) {
//         return res
//           .status(400)
//           .json({ error: "Expected challenge is missing from session." });
//       }

//       const webAuthnCredential = {
//         credentialPublicKey: isoBase64URL.toBuffer(
//           response.credential.publicKey
//         ),
//         credentialID: isoBase64URL.toBuffer(response.credential.id),
//         transports: response.credential.transports,
//       };

//       const verificationCredentials: WebAuthnCredential = {
//         id: isoBase64URL.fromBuffer(webAuthnCredential.credentialID),
//         publicKey: webAuthnCredential.credentialPublicKey,
//         counter: response.credential.counter,
//       };

//       const { verified } = await verifyAuthenticationResponse({
//         response,
//         credential: verificationCredentials,
//         expectedChallenge,
//         expectedOrigin,
//         expectedRPID,
//         requireUserVerification: false,
//       });
//       if (!verified) {
//         return res.status(400).json({ error: "Authentication failed" });
//       }
//       delete req.session.challenge;
//       req.session.username = user.userName;
//       req.session.signedIn = true;

//       return res.json(user);
//     } catch (error: any) {
//       delete req.session.challenge;
//       console.log(error);
//       return res.status(400).json({ error: error.message });
//     }
//   }
// );
// app.post(
//   "/signinResponse",
//   async (req: Request, res: Response, next: NextFunction) => {
//     try {
//       const { response, userId } = req.body;

//       console.log(req.session);

//       const expectedChallenge = req.session.challenge;
//       console.log(expectedChallenge);
//       const expectedRPID = "localhost";
//       const expectedOrigin =
//         req.get("origin") || `${req.protocol}://${req.get("host")}`;

//       if (!expectedChallenge) {
//         return res
//           .status(400)
//           .json({ error: "Missing challenge from session." });
//       }

//       const credential = await Credentials.findOne({
//         credentialId: response.id,
//       });
//       if (!credential)
//         return res.status(400).json({ error: "Invalid credential id" });

//       const user = await User.findById(userId);
//       if (!user) return res.status(400).json({ error: "User not found" });

//       const verificationCredentials: WebAuthnCredential = {
//         id: isoBase64URL.fromBuffer(response.credential.id),
//         publicKey: response.credential.publicKey,
//         counter: response.credential.counter,
//       };

//       const { verified } = await verifyAuthenticationResponse({
//         response,
//         credential: verificationCredentials,
//         expectedChallenge,
//         expectedOrigin,
//         expectedRPID,
//         requireUserVerification: false,
//       });

//       if (!verified)
//         return res.status(400).json({ error: "Authentication failed" });

//       delete req.session.challenge;
//       req.session.username = user.userName;
//       req.session.signedIn = true;

//       return res.json(user);
//     } catch (error: any) {
//       console.error("Error during signinResponse:", error);
//       return res.status(500).json({ error: error.message });
//     }
//   }
// );

app.post(
  "/signinResponse",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      console.log("Session Data in signinResponse:", req.session);
      console.log("Session ID", req.sessionID);

      const { response, userId } = req.body;
      console.log(response, userId);
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const expectedChallenge = req.session.challenge;
      const expectedRPID = "passkey-demos.onrender.com";
      const expectedOrigin =
        req.get("origin") || `${req.protocol}://${req.get("host")}`;

      if (!expectedChallenge) {
        return res
          .status(400)
          .json({ error: "Missing challenge from session." });
      }

      const exitingCredential = await Credentials.findOne({
        credentialId: response.id,
      });

      if (!exitingCredential)
        return res.status(400).json({ error: "Invalid credential id" });

      console.log(
        exitingCredential,
        "--------------------------------------------yah-------------------------------",
        exitingCredential.id
      );

      const publicKeyBuffer = exitingCredential.publicKey;
      const publicKeyUint8Array = new Uint8Array(publicKeyBuffer);

      const { verified } = await verifyAuthenticationResponse({
        response,
        credential: {
          id: exitingCredential.id,
          publicKey: publicKeyUint8Array,
          counter: exitingCredential.counter || 0,
          transports:
            exitingCredential.transports as AuthenticatorTransportFuture[],
        },
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
      });

      if (!verified) {
        return res.status(400).json({ error: "Authentication failed" });
      }

      // Clear the challenge and set user data in the session
      delete req.session.challenge;
      req.session.signedIn = true;

      console.log("Updated Session Data:", req.session);

      return res.json(user);
    } catch (error: any) {
      console.error("Error during signinResponse:", error);
      return res.status(500).json({ error: error.message });
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
