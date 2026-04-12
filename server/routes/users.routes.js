const express = require("express");
const bcrypt = require("bcryptjs");
const { ObjectId } = require("mongodb");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");

const usersRoutes = ({ collections, authenticate, authorizeRoles }) => {
  const router = express.Router();
  const { userCollection } = collections;

  router.get(
    "/profile",
    authenticate,
    asyncHandler(async (req, res) => {
      const user = await userCollection.findOne(
        { email: req.user.email },
        { projection: { password: 0 } },
      );
      if (!user) throw new ApiError(404, "User not found");
      res.status(200).json({ success: true, data: user });
    }),
  );

  router.post(
    "/users",
    asyncHandler(async (req, res) => {
      const userInfo = req.body;
      const existingUser = await userCollection.findOne({ email: userInfo.email });
      if (existingUser) throw new ApiError(409, "User already exists with this email");

      if (userInfo.password) {
        userInfo.password = await bcrypt.hash(userInfo.password, 10);
      }

      userInfo.createdAt = new Date();
      userInfo.updatedAt = new Date();
      userInfo.status = userInfo.status || "active";
      userInfo.role = userInfo.role || "buyer";
      userInfo.photoURL = userInfo.photoURL || "https://i.ibb.co/0jZqyvJ/user.png";

      const result = await userCollection.insertOne(userInfo);
      const { password, ...userWithoutPassword } = userInfo;

      res.status(201).json({
        success: true,
        message: "User created successfully",
        data: { ...userWithoutPassword, _id: result.insertedId },
      });
    }),
  );

  router.get(
    "/users",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      const {
        page = 1,
        limit = 10,
        searchText = "",
        role = "all",
        status = "all",
      } = req.query;
      const pageNumber = Number(page);
      const pageSize = Number(limit);
      const skip = (pageNumber - 1) * pageSize;

      const filter = {};
      if (searchText.trim()) {
        filter.$or = [
          { name: { $regex: searchText, $options: "i" } },
          { email: { $regex: searchText, $options: "i" } },
          { displayName: { $regex: searchText, $options: "i" } },
        ];
      }
      if (role !== "all") filter.role = role;
      if (status !== "all") filter.status = status;

      const total = await userCollection.countDocuments(filter);
      const users = await userCollection
        .find(filter, { projection: { password: 0 } })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageSize)
        .toArray();

      res.status(200).json({
        success: true,
        data: users,
        total,
        totalPages: Math.ceil(total / pageSize),
        currentPage: pageNumber,
        perPage: pageSize,
      });
    }),
  );

  router.get(
    "/users/email/:email",
    asyncHandler(async (req, res) => {
      const user = await userCollection.findOne(
        { email: req.params.email },
        { projection: { password: 0 } },
      );

      if (!user) {
        return res.status(200).json({
          success: false,
          data: null,
          message: "User not found",
        });
      }

      res.status(200).json({
        success: true,
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
          photoURL: user.photoURL,
          role: user.role,
        },
      });
    }),
  );

  router.get(
    "/users/role/:email",
    asyncHandler(async (req, res) => {
      const user = await userCollection.findOne(
        { email: req.params.email },
        { projection: { password: 0 } },
      );

      if (!user) return res.status(200).json({ role: "user", exists: false });
      return res.status(200).json({ role: user.role || "user", exists: true });
    }),
  );

  router.patch(
    "/users/role/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid user ID");
      const { role } = req.body;
      await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role, updatedAt: new Date() } },
      );
      res.status(200).json({ success: true, message: `User role updated to ${role}` });
    }),
  );

  router.patch(
    "/users/status/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid user ID");
      const { status, suspendReason = "", suspendFeedback = "" } = req.body;
      await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        {
          $set: { status, suspendReason, suspendFeedback, updatedAt: new Date() },
        },
      );
      res.status(200).json({
        success: true,
        message: `User status updated to ${status}`,
      });
    }),
  );

  return router;
};

module.exports = usersRoutes;
