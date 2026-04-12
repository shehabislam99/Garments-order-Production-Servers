const jwt = require("jsonwebtoken");
const ApiError = require("../utils/apiError");
const { verifyFirebaseToken } = require("../services/firebase");

const authenticate = (collections) => async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      throw new ApiError(401, "Unauthorized access");
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role || "buyer",
      };
      return next();
    } catch (jwtError) {
      const fbDecoded = await verifyFirebaseToken(token);
      if (!fbDecoded?.email) {
        throw new ApiError(401, "Unauthorized access");
      }

      const user = await collections.userCollection.findOne({
        email: fbDecoded.email,
      });

      if (!user) {
        throw new ApiError(401, "Unauthorized access");
      }

      req.user = {
        id: user._id.toString(),
        email: user.email,
        role: user.role || "buyer",
      };
      return next();
    }
  } catch (error) {
    return next(error);
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  const role = req.user?.role;
  if (!role || !roles.includes(role)) {
    return next(new ApiError(403, "Forbidden access"));
  }
  return next();
};

module.exports = {
  authenticate,
  authorizeRoles,
};
