// custom.d.ts

import "express-session";
import "express-serve-static-core";

declare module "express-session" {
  interface SessionData {
    challenge?: string;
    username: string;
    signedIn?: boolean;
  }
}

declare module "express-serve-static-core" {
  interface Request {
    useragent?: {
      platform?: string;
    };
  }
}
