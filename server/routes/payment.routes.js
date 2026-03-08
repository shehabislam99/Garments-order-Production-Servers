const express = require("express");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");

const paymentRoutes = ({ collections, authenticate }) => {
  const router = express.Router();
  const { orderCollection } = collections;
  const stripe = require("stripe")(process.env.STRIPE_SECRET);

  router.post(
    "/payment-checkout-session",
    authenticate,
    asyncHandler(async (req, res) => {
      const { orderamount, product_name, orderId, CustomerEmail, trackingId } = req.body;
      const amount = Math.round(Number(orderamount || 0) * 100);
      if (!amount || amount < 1) throw new ApiError(400, "Invalid order amount");

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: product_name || "Order Payment",
                description: `Tracking ID: ${trackingId || "N/A"}`,
              },
              unit_amount: amount,
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: { orderId: orderId || "", trackingId: trackingId || "" },
        customer_email: CustomerEmail || req.user.email,
        success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_URL}/payment-canceled`,
      });

      res.json({ success: true, url: session.url, session_id: session.id });
    }),
  );

  router.patch(
    "/payment-success",
    asyncHandler(async (req, res) => {
      const { session_id } = req.query;
      if (!session_id) throw new ApiError(400, "session_id is required");

      const session = await stripe.checkout.sessions.retrieve(session_id);
      if (session.payment_status !== "paid") throw new ApiError(400, "Payment not completed");

      const trackingId = session.metadata?.trackingId;
      await orderCollection.updateOne(
        { trackingId },
        {
          $set: {
            paymentStatus: "paid",
            transactionId: session.payment_intent,
            paidAt: new Date(),
            updatedAt: new Date(),
          },
        },
      );

      res.json({
        success: true,
        transactionId: session.payment_intent,
        trackingId,
        amount: (session.amount_total || 0) / 100,
      });
    }),
  );

  return router;
};

module.exports = paymentRoutes;
