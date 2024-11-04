import mongoose from "mongoose";

const AuthOptionsSchema = new mongoose.Schema({
  userClientId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    unique: true,
    ref: "User",
  },
  userId: {
    type: String,
    required: true,
    unique: true,
  },
  challenge: {
    type: String,
    required: true,
  },
  timeout: {
    type: Number,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export const AuthOptions = mongoose.model("AuthOptions", AuthOptionsSchema);
