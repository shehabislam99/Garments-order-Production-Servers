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
      const [
        totalOrders,
        revenueResult,
        activeUsers,
        recentOrders,
        categoryBuckets,
      ] = await Promise.all([
        orderCollection.countDocuments({}),
        orderCollection
          .aggregate([
            {
              $group: {
                _id: null,
                totalRevenue: {
                  $sum: {
                    $ifNull: [{ $toDouble: "$totalPrice" }, 0],
                  },
                },
              },
            },
          ])
          .toArray(),
        userCollection.countDocuments({}),
        orderCollection
          .find({})
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray(),
        orderCollection
          .aggregate([
            {
              $group: {
                _id: {
                  $ifNull: ["$category", "$product_name", "Uncategorized"],
                },
                value: {
                  $sum: {
                    $ifNull: [{ $toDouble: "$totalPrice" }, 0],
                  },
                },
              },
            },
            { $sort: { value: -1 } },
            { $limit: 6 },
            {
              $project: {
                category: "$_id",
                value: 1,
                _id: 0,
              },
            },
          ])
          .toArray(),
      ]);

      const metrics = {
        totalOrders,
        revenue: revenueResult[0]?.totalRevenue || 0,
        activeUsers,
      };

      res.status(200).json({
        success: true,
        data: {
          metrics,
          categories: categoryBuckets,
          recentOrders,
        },
      });
    }),
  );

  return router;
};

module.exports = statsRoutes;
