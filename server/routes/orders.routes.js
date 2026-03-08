const express = require("express");
const crypto = require("crypto");
const { ObjectId } = require("mongodb");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");

const generateTrackingId = () => {
  const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `TRK${timestamp}${random}`;
};

const toObjectIdOrNull = (id) => (ObjectId.isValid(id) ? new ObjectId(id) : null);

const ordersRoutes = ({ collections, authenticate, authorizeRoles }) => {
  const router = express.Router();
  const { orderCollection, paymentCollection, trackingCollection } = collections;

  router.post(
    "/orders",
    authenticate,
    asyncHandler(async (req, res) => {
      const orderData = req.body;
      const trackingId = generateTrackingId();
      const isStripe = orderData.paymentMethod === "Stripe";

      const order = {
        ...orderData,
        CustomerEmail: req.user.email,
        trackingId,
        status: "pending",
        paymentStatus: isStripe ? "paid" : "cod",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await orderCollection.insertOne(order);
      await paymentCollection.insertOne({
        amount: order.totalPrice || 0,
        currency: "usd",
        email: order.CustomerEmail,
        paymentStatus: order.paymentStatus,
        transactionId: isStripe ? orderData.transactionId || null : null,
        trackingId,
        createdAt: new Date(),
      });

      res.status(201).json({
        success: true,
        order: {
          _id: result.insertedId,
          trackingId,
          totalPrice: order.totalPrice,
          paymentMethod: order.paymentMethod,
          status: order.status,
          paymentStatus: order.paymentStatus,
        },
        message: "Order created successfully",
      });
    }),
  );

  router.get(
    "/orders",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      const { status, search, page = 1, limit = 10 } = req.query;
      const pageNumber = Number(page);
      const limitNumber = Number(limit);
      const skip = (pageNumber - 1) * limitNumber;

      const query = {};
      if (status && status !== "all") query.status = status;

      if (typeof search === "string" && search.trim() !== "") {
        const searchRegex = new RegExp(search.trim(), "i");
        query.$or = [
          { CustomerEmail: searchRegex },
          { orderId: searchRegex },
          { trackingId: searchRegex },
          { product_name: searchRegex },
          { status: searchRegex },
          { paymentStatus: searchRegex },
        ];
      }

      const [orders, total] = await Promise.all([
        orderCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limitNumber)
          .toArray(),
        orderCollection.countDocuments(query),
      ]);

      res.status(200).json({
        success: true,
        data: orders,
        total,
        page: pageNumber,
        totalPages: Math.ceil(total / limitNumber),
        limit: limitNumber,
      });
    }),
  );

  router.get(
    "/order/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      const rawId = req.params.id;
      const objectId = toObjectIdOrNull(rawId);

      let order = null;
      if (objectId) {
        order = await orderCollection.findOne({ _id: objectId });
      }
      if (!order) {
        order = await orderCollection.findOne({ orderId: rawId });
      }
      if (!order) throw new ApiError(404, "Order not found");

      res.status(200).json({ success: true, data: order });
    }),
  );

  router.get(
    "/my-orders",
    authenticate,
    asyncHandler(async (req, res) => {
      const { searchText = "", page = 1, limit = 10, status = "all" } = req.query;
      const filterQuery = { CustomerEmail: req.user.email };

      if (searchText.trim()) {
        filterQuery.$or = [
          { orderId: { $regex: searchText, $options: "i" } },
          { "product.name": { $regex: searchText, $options: "i" } },
        ];
      }
      if (status !== "all") filterQuery.status = status;

      const pageNumber = Number(page);
      const pageSize = Number(limit);
      const skip = (pageNumber - 1) * pageSize;
      const total = await orderCollection.countDocuments(filterQuery);
      const orders = await orderCollection
        .find(filterQuery)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageSize)
        .toArray();

      res.json({
        success: true,
        data: orders,
        total,
        page: pageNumber,
        totalPages: Math.ceil(total / pageSize),
      });
    }),
  );

  router.patch(
    "/my-orders/cancel/:id",
    authenticate,
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid ID");

      await orderCollection.updateOne(
        { _id: new ObjectId(req.params.id), CustomerEmail: req.user.email },
        { $set: { status: "cancelled", updatedAt: new Date() } },
      );

      res.json({ success: true, message: "Order cancelled successfully" });
    }),
  );

  router.put(
    "/orders/status/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid order ID");
      const { status, rejectionReason, approvedAt, rejectedAt } = req.body;
      if (!["approved", "rejected"].includes(status)) {
        throw new ApiError(400, "Invalid status. Must be 'approved' or 'rejected'");
      }

      const updateData = { status, updatedAt: new Date() };
      if (status === "approved") {
        updateData.approvedAt = approvedAt ? new Date(approvedAt) : new Date();
      }
      if (status === "rejected") {
        updateData.rejectionReason = rejectionReason || "Rejected by manager";
        updateData.rejectedAt = rejectedAt ? new Date(rejectedAt) : new Date();
      }

      const result = await orderCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData },
      );
      if (!result.matchedCount) throw new ApiError(404, "Order not found");

      const updatedOrder = await orderCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      res.status(200).json({
        success: true,
        message: `Order ${status} successfully`,
        data: updatedOrder,
      });
    }),
  );

  router.post(
    "/orders/tracking/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid order ID");
      const { location, note, status } = req.body;
      if (!location || !location.trim()) throw new ApiError(400, "Location is required");

      const order = await orderCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!order) throw new ApiError(404, "Order not found");

      const trackingEntry = {
        location,
        note: note || "",
        status: status || "Order Processing",
        dateTime: new Date(),
      };

      await trackingCollection.updateOne(
        { orderId: order._id },
        { $push: { history: trackingEntry }, $set: { lastUpdated: new Date() } },
        { upsert: true },
      );

      res.status(200).json({
        success: true,
        message: "Tracking added successfully",
        data: trackingEntry,
      });
    }),
  );

  const timelineHandler = async (req, res) => {
    const { orderId } = req.params;
    const maybeObjectId = toObjectIdOrNull(orderId);

    const orderData = await orderCollection.findOne({
      $or: [{ _id: maybeObjectId }, { orderId }],
    });
    if (!orderData) throw new ApiError(404, "Order not found");

    if (
      !["admin", "manager"].includes(req.user.role) &&
      orderData.CustomerEmail !== req.user.email
    ) {
      throw new ApiError(403, "Forbidden access");
    }

    const trackingDoc = await trackingCollection.findOne({ orderId: orderData._id });
    if (!trackingDoc) {
      return res.status(200).json({
        success: true,
        data: { order: orderData, timeline: [] },
        message: "No tracking history found",
      });
    }

    const timeline = trackingDoc.history
      .map((log, index) => ({
        id: index,
        step: log.status,
        Note: log.note || "No additional details",
        location: log.location || "Unknown",
        status:
          log.status === "product_delivered"
            ? "completed"
            : index === trackingDoc.history.length - 1
              ? "current"
              : "completed",
        date: log.dateTime,
      }))
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    return res.status(200).json({
      success: true,
      data: { order: orderData, timeline },
      message: "Timeline fetched successfully",
    });
  };

  router.get(
    "/admin/orderTracking/:orderId",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(timelineHandler),
  );

  router.get(
    "/track-order/timeline/:orderId",
    authenticate,
    asyncHandler(timelineHandler),
  );

  return router;
};

module.exports = ordersRoutes;
