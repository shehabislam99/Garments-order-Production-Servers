const express = require("express");
const asyncHandler = require("../utils/asyncHandler");

const statsRoutes = ({ collections, authenticate, authorizeRoles }) => {
  const router = express.Router();
  const { productCollection, orderCollection, userCollection, paymentCollection } =
    collections;

  router.get(
    "/admin/stats",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      const [allProducts, allOrders, allUsers, totalRevenueAgg, pendingOrders] =
        await Promise.all([
          productCollection.countDocuments({}),
          orderCollection.countDocuments({}),
          userCollection.countDocuments({}),
          paymentCollection
            .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
            .toArray(),
          orderCollection.countDocuments({ status: "pending" }),
        ]);

      res.status(200).json({
        success: true,
        data: {
          allProducts,
          pendingOrders,
          allUsers,
          allOrders,
          totalRevenue: totalRevenueAgg[0]?.total || 0,
        },
      });
    }),
  );

  router.get(
    "/manager/stats",
    authenticate,
    authorizeRoles("manager", "admin"),
    asyncHandler(async (req, res) => {
      const [allProducts, approvedOrders, pendingOrders] = await Promise.all([
        productCollection.countDocuments({ createdByEmail: req.user.email }),
        orderCollection.countDocuments({ status: "approved" }),
        orderCollection.countDocuments({ status: "pending" }),
      ]);

      res.status(200).json({
        success: true,
        data: { allProducts, pendingOrders, approvedOrders },
      });
    }),
  );

  router.get(
    "/buyer/stats",
    authenticate,
    asyncHandler(async (req, res) => {
      const [totalOrders, pendingPayment, payments] = await Promise.all([
        orderCollection.countDocuments({ CustomerEmail: req.user.email }),
        orderCollection.countDocuments({
          CustomerEmail: req.user.email,
          paymentStatus: "cod",
        }),
        paymentCollection.find({ email: req.user.email }).toArray(),
      ]);

      const totalSpent = payments.reduce((sum, p) => sum + (Number(p.amount) || 0), 0);
      res.status(200).json({
        success: true,
        data: { totalOrders, pendingPayment, totalSpent },
      });
    }),
  );

  router.get(
    "/admin/analytics",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      const [totalOrders, totalProducts, totalRevenue] = await Promise.all([
        orderCollection.countDocuments({}),
        productCollection.countDocuments({}),
        orderCollection
          .aggregate([
            { $match: { status: "delivered" } },
            { $group: { _id: null, total: { $sum: "$totalAmount" } } },
          ])
          .toArray(),
      ]);

      res.status(200).json({
        success: true,
        data: {
          summary: {
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders,
            newCustomers: 0,
            productsSold: 0,
            avgOrderValue:
              totalOrders > 0 ? (totalRevenue[0]?.total || 0) / totalOrders : 0,
            conversionRate: 0,
          },
        },
        message: "Analytics data fetched successfully",
      });
    }),
  );

  return router;
};

module.exports = statsRoutes;
