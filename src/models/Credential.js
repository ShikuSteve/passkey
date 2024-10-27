import mongoose from "mongoose";

const credentialsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    
  },
  credentialId: {
    type: String,
    required: true,
    unique: true,
  },
  publicKey: { type: String, required: true },
  transports: [String],
  backed_up: { type: Boolean, default: true },
  name: { type: String, default: "default" },
});

export const Credentials = mongoose.model("Credentials", credentialsSchema);
