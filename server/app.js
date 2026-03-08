const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { connectDB } = require("./config/db");
const { initializeFirebase } = require("./services/firebase");
const errorHandler = require("./middleware/errorHandler");
const { authenticate, authorizeRoles } = require("./middleware/auth");
const authRoutes = require("./routes/auth.routes");
const usersRoutes = require("./routes/users.routes");
const productsRoutes = require("./routes/products.routes");
const ordersRoutes = require("./routes/orders.routes");
const paymentRoutes = require("./routes/payment.routes");
const statsRoutes = require("./routes/stats.routes");

const createApp = async () => {
  initializeFirebase();
  const collections = await connectDB();

  const app = express();
  app.use(helmet());
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN?.split(",") || "*",
      credentials: true,
    }),
  );
  app.use(express.json({ limit: "1mb" }));

  if (process.env.NODE_ENV !== "production") {
    app.use(morgan("dev"));
  }

  const auth = authenticate(collections);

  app.get("/", (req, res) => {
    res.status(200).send("Garments production tracker server is running");
  });

  app.use("/api/auth", authRoutes({ collections, authenticate: auth }));
  app.use(usersRoutes({ collections, authenticate: auth, authorizeRoles }));
  app.use(productsRoutes({ collections, authenticate: auth, authorizeRoles }));
  app.use(ordersRoutes({ collections, authenticate: auth, authorizeRoles }));
  app.use(paymentRoutes({ collections, authenticate: auth }));
  app.use(statsRoutes({ collections, authenticate: auth, authorizeRoles }));

  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: "Route not found",
    });
  });

  app.use(errorHandler);

  return app;
};

module.exports = createApp;
