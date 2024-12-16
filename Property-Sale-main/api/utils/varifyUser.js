import jwt from "jsonwebtoken";
import { throwError } from "./error.js";

export const verifyToken = (req, res, next) => {
  const tooken = req.cookies.access_token;
  if (!tooken) return next(throwError(401, "Session End. Login Again! "));
  jwt.verify(tooken, "e0a173dfb0597bdcbc239b34337583832c8c4c0c6b13cf49a21058091b713758", (err, user) => {
    if (err) return next(throwError(403, "Forbidden"));
    req.user = user;
    next();
  });
};
