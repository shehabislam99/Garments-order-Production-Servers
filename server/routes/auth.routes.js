const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body } = require("express-validator");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");
const { validatePassword } = require("../utils/password");
const validateRequest = require("../middleware/validate");

const generateToken = (user) =>
  jwt.sign(
    { id: user._id.toString(), email: user.email, role: user.role || "user" },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "30d" },
  );

const createProfileHandlers = ({ userCollection }) => {
  const updateProfile = asyncHandler(async (req, res) => {
    const { name, photoURL } = req.body;
    const updateData = {
      ...(name && { name }),
      ...(photoURL && { photoURL }),
      updatedAt: new Date(),
    };

    const result = await userCollection.updateOne(
      { email: req.user.email },
      { $set: updateData },
    );

    if (!result.matchedCount) throw new ApiError(404, "User not found");

    const user = await userCollection.findOne(
      { email: req.user.email },
      { projection: { password: 0 } },
    );

    res.json({
      success: true,
      message: "Profile updated successfully",
      data: user,
    });
  });

  const changePassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      throw new ApiError(400, passwordValidation.errors.join(", "));
    }

    const user = await userCollection.findOne({ email: req.user.email });
    if (!user) throw new ApiError(404, "User not found");
    if (!user.password && currentPassword) {
      throw new ApiError(
        400,
        "No password is set for this account; please leave current password blank and just provide a new password.",
      );
    }
    if (!user.password && !currentPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await userCollection.updateOne(
        { _id: user._id },
        { $set: { password: hashedPassword, updatedAt: new Date() } },
      );
      return res.json({ success: true, message: "Password set successfully" });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) throw new ApiError(401, "Current password is incorrect");

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await userCollection.updateOne(
      { _id: user._id },
      { $set: { password: hashedPassword, updatedAt: new Date() } },
    );

    res.json({ success: true, message: "Password changed successfully" });
  });

  return { updateProfile, changePassword };
};

const authRoutes = ({ collections, authenticate }) => {
  const router = express.Router();
  const { userCollection } = collections;
  const { updateProfile, changePassword } = createProfileHandlers({
    userCollection,
  });

  router.post(
    "/register",
    [
      body("name").trim().notEmpty().withMessage("Name is required"),
      body("email").isEmail().withMessage("Valid email is required"),
      body("password").notEmpty().withMessage("Password is required"),
    ],
    validateRequest,
    asyncHandler(async (req, res) => {
      const { name, email, password, photoURL, role = "user" } = req.body;

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        throw new ApiError(400, passwordValidation.errors.join(", "));
      }

      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        throw new ApiError(409, "User already exists with this email");
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const safeRole = ["admin", "manager", "buyer"].includes(role)
        ? role
        : "buyer";

      const newUser = {
        name,
        email,
        password: hashedPassword,
        photoURL: photoURL || "https://i.ibb.co/0jZqyvJ/user.png",
        role: safeRole,
        status: "active",
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLogin: null,
      };

      const result = await userCollection.insertOne(newUser);
      const insertedUser = { ...newUser, _id: result.insertedId };
      const token = generateToken(insertedUser);
      const { password: _password, ...userWithoutPassword } = insertedUser;

      res.status(201).json({
        success: true,
        message: "User created successfully",
        data: userWithoutPassword,
        token,
      });
    }),
  );

  router.post(
    "/login",
    [
      body("email").isEmail().withMessage("Valid email is required"),
      body("password").notEmpty().withMessage("Password is required"),
    ],
    validateRequest,
    asyncHandler(async (req, res) => {
      const { email, password } = req.body;

      const user = await userCollection.findOne({ email });
      if (!user) throw new ApiError(401, "Invalid email or password");

      if (user.status === "suspended") {
        throw new ApiError(
          403,
          user.suspendFeedback || "Your account has been suspended",
        );
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) throw new ApiError(401, "Invalid email or password");

      await userCollection.updateOne(
        { _id: user._id },
        { $set: { lastLogin: new Date(), updatedAt: new Date() } },
      );

      const token = generateToken(user);
      const { password: _password, ...userWithoutPassword } = user;

      res.json({
        success: true,
        message: "Login successful",
        data: userWithoutPassword,
        token,
      });
    }),
  );

  router.get(
    "/me",
    authenticate,
    asyncHandler(async (req, res) => {
      const user = await userCollection.findOne(
        { email: req.user.email },
        { projection: { password: 0 } },
      );
      if (!user) throw new ApiError(404, "User not found");
      res.json({ success: true, data: user });
    }),
  );

  router.patch("/profile", authenticate, updateProfile);
  router.patch(
    "/change-password",
    authenticate,
    [
      body("currentPassword")
        .notEmpty()
        .withMessage("Current password is required"),
      body("newPassword").notEmpty().withMessage("New password is required"),
    ],
    validateRequest,
    changePassword,
  );

  return router;
};

const profileRoutes = ({ collections, authenticate }) => {
  const router = express.Router();
  const { userCollection } = collections;
  const { updateProfile, changePassword } = createProfileHandlers({
    userCollection,
  });

  router.patch("/profile", authenticate, updateProfile);
  router.patch("/change-password", authenticate, changePassword);

  return router;
};

module.exports = {
  authRoutes,
  profileRoutes,
};
