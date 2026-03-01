const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3000;
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

//keyConverter
const admin = require("firebase-admin");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8",
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//middleware
app.use(express.json());
app.use(cors());

// Password validation function
const validatePassword = (password) => {
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasMinLength = password.length >= 6;

  return {
    isValid: hasUppercase && hasLowercase && hasMinLength,
    errors: [
      !hasUppercase && "Must have an Uppercase letter",
      !hasLowercase && "Must have a Lowercase letter",
      !hasMinLength && "Length must be at least 6 characters",
    ].filter(Boolean),
  };
};

// JWT Token generation
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};


const verifyManager = async (req, res, next) => {
  const email = req.decoded_email;
  const query = { email };
  const user = await userCollection.findOne(query);

  if (!user || user.role !== "manager") {
    return res.status(403).send({ message: "forbidden access" });
  }

  next();
};



const stripe = require("stripe")(process.env.STRIPE_SECRET);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.Db_USERNAME}:${process.env.Db_Password}@cluster0.pealo3m.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // await client.connect();
    const db = client.db("Garments_production");
    const userCollection = db.collection("user");
    const productCollection = db.collection("products");
    const orderCollection = db.collection("orders");
    const paymentCollection = db.collection("payment");
    const trackingCollection = db.collection("tracking");

  

    // Register new user with bcrypt
    app.post("/api/auth/register", async (req, res) => {
      try {
        const { name, email, password, photoURL, role = "buyer" } = req.body;

        // Validate password
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
          return res.status(400).json({
            success: false,
            message: passwordValidation.errors.join(", "),
          });
        }

        // Check if user already exists
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: "User already exists with this email",
          });
        }

        // Hash password with bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user object
        const newUser = {
          name,
          email,
          password: hashedPassword,
          photoURL: photoURL || "https://i.ibb.co/0jZqyvJ/user.png",
          role,
          status: "active",
          createdAt: new Date(),
          updatedAt: new Date(),
          lastLogin: null,
        };

        // Insert user into database
        const result = await userCollection.insertOne(newUser);

        // Generate JWT token
        const token = generateToken(result.insertedId, role);

        // Remove password from response
        const { password: _, ...userWithoutPassword } = newUser;

        res.status(201).json({
          success: true,
          message: "User created successfully",
          data: {
            ...userWithoutPassword,
            _id: result.insertedId,
          },
          token,
        });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({
          success: false,
          message: "Server error during registration",
        });
      }
    });

    // Login with bcrypt password verification
    app.post("/api/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        // Find user by email
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({
            success: false,
            message: "Invalid email or password",
          });
        }

        // Check if user is active
        if (user.status === "suspended") {
          return res.status(403).json({
            success: false,
            message: user.suspendFeedback || "Your account has been suspended",
          });
        }

        // Verify password with bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({
            success: false,
            message: "Invalid email or password",
          });
        }

        // Update last login
        await userCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              lastLogin: new Date(),
              updatedAt: new Date(),
            },
          },
        );

        // Generate token
        const token = generateToken(user._id, user.role);

        // Remove password from response
        const { password: _, ...userWithoutPassword } = user;

        res.json({
          success: true,
          message: "Login successful",
          data: userWithoutPassword,
          token,
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({
          success: false,
          message: "Server error during login",
        });
      }
    });

    // Get current user
    app.get("/api/auth/me", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne(
          { email },
          { projection: { password: 0 } },
        );

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        res.json({
          success: true,
          data: user,
        });
      } catch (error) {
        console.error("Get user error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // Update user profile
    app.patch("/api/auth/profile", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { name, photoURL } = req.body;

        const updateData = {
          ...(name && { name }),
          ...(photoURL && { photoURL }),
          updatedAt: new Date(),
        };

        const result = await userCollection.updateOne(
          { email },
          { $set: updateData },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        const updatedUser = await userCollection.findOne(
          { email },
          { projection: { password: 0 } },
        );

        res.json({
          success: true,
          message: "Profile updated successfully",
          data: updatedUser,
        });
      } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // Change password with bcrypt
    app.patch("/api/auth/change-password", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { currentPassword, newPassword } = req.body;

        // Validate new password
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) {
          return res.status(400).json({
            success: false,
            message: passwordValidation.errors.join(", "),
          });
        }

        // Get user with password
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        // Verify current password with bcrypt
        const isPasswordValid = await bcrypt.compare(
          currentPassword,
          user.password,
        );
        if (!isPasswordValid) {
          return res.status(401).json({
            success: false,
            message: "Current password is incorrect",
          });
        }

        // Hash new password with bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await userCollection.updateOne(
          { email },
          {
            $set: {
              password: hashedPassword,
              updatedAt: new Date(),
            },
          },
        );

        res.json({
          success: true,
          message: "Password changed successfully",
        });
      } catch (error) {
        console.error("Password change error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // ============ PAYMENT ENDPOINTS ============

    app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
      const { orderamount, product_name, orderId, CustomerEmail, trackingId } =
        req.body;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: product_name,
                description: `Tracking ID: ${trackingId}`,
              },
              unit_amount: Math.round(orderamount * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          orderId,
          trackingId,
        },
        customer_email: CustomerEmail,
        success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_URL}/payment-canceled`,
      });

      res.json({
        success: true,
        url: session.url,
        session_id: session.id,
      });
    });

    app.patch("/payment-success", async (req, res) => {
      const { session_id } = req.query;
      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (session.payment_status !== "paid") {
        return res.status(400).json({
          success: false,
          message: "Payment not completed",
        });
      }

      const trackingId = session.metadata.trackingId;
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
        amount: session.amount_total / 100,
      });
    });

    // ============ PROFILE ENDPOINT ============

    app.get("/profile", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;
      const user = await userCollection.findOne({ email });

      const { password, ...userData } = user;

      res.status(200).json({
        success: true,
        data: userData,
      });
    });

    // ============ TRACKING ID GENERATOR ============

    const generateTrackingId = () => {
      const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const random = crypto.randomBytes(3).toString("hex").toUpperCase();
      return `TRK${timestamp}${random}`;
    };

    // ============ ORDERS ENDPOINTS ============

    app.post("/orders", verifyFBToken, async (req, res) => {
      const orderData = req.body;
      const trackingId = generateTrackingId();

      const isStripe = orderData.paymentMethod === "Stripe";

      const order = {
        ...orderData,
        trackingId,
        status: "pending",
        paymentStatus: isStripe ? "paid" : "cod",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await orderCollection.insertOne(order);
      await paymentCollection.insertOne({
        amount: order.totalPrice,
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
    });

    app.get("/order/:id", verifyFBToken, verifyManager, async (req, res) => {
      const { id } = req.params;
      let order = await orderCollection.findOne({ _id: new ObjectId(id) });
      if (!order) {
        order = await orderCollection.findOne({ orderId: id });
      }
      if (!order) {
        return res
          .status(404)
          .json({ success: false, message: "Order not found" });
      }

      res.status(200).json({
        success: true,
        data: order,
      });
    });

    // ============ STATS ENDPOINTS ============

    app.get("/admin/stats", async (req, res) => {
      const allProducts = await productCollection.countDocuments({});
      const allOrders = await orderCollection.countDocuments({
        payment_options: { $ne: "PayFirst" },
      });
      const allUsers = await userCollection.countDocuments({});

      const totalRevenue = await paymentCollection
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();

      const pendingOrders = await orderCollection.countDocuments({
        payment_status: "pending",
      });
      res.send({
        success: true,
        data: {
          allProducts,
          pendingOrders,
          allUsers,
          allOrders,
          totalRevenue: totalRevenue[0]?.total || 0,
        },
      });
    });

    app.get(
      "/manager/stats",
 
      async (req, res) => {
        const email = req.decoded_email;

        const allProducts = await productCollection.countDocuments({
          createdByEmail: email,
        });

        const approvedOrders = await orderCollection.countDocuments({
          status: "approved",
        });

        const pendingOrders = await orderCollection.countDocuments({
          status: "pending",
        });

        res.send({
          success: true,
          data: {
            allProducts,
            pendingOrders,
            approvedOrders,
          },
        });
      },
    );

    app.get("/buyer/stats", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;

      const totalOrders = await orderCollection.countDocuments({
        CustomerEmail: email,
      });

      const pendingPayment = await orderCollection.countDocuments({
        CustomerEmail: email,
        paymentStatus: "cod",
      });

      const payments = await paymentCollection.find({ email: email }).toArray();
      const totalSpent = payments.reduce((sum, p) => sum + (p.amount || 0), 0);

      res.send({
        success: true,
        data: {
          totalOrders,
          pendingPayment,
          totalSpent,
        },
      });
    });

    // ============ PRODUCTS ENDPOINTS ============

    app.post("/products", async (req, res) => {
      const product = req.body;
      const newProduct = {
        ...product,
        createdAt: new Date(),
      };
      const result = await productCollection.insertOne(newProduct);
      res.send(result);
      res.json({
        success: true,
        message: "Product received",
        data: req.body,
      });
    });

    app.get("/products", async (req, res) => {
      const email = req.decoded_email;
      const {
        searchText = "",
        page = 1,
        limit = 10,
        category = "all",
        Pstatus = "all",
      } = req.query;

      const filterQuery = {
        ...(email && { createdByEmail: email }),
        ...(searchText && {
          $or: [
            { product_name: { $regex: searchText, $options: "i" } },
            { description: { $regex: searchText, $options: "i" } },
            { category: { $regex: searchText, $options: "i" } },
          ],
        }),
        ...(category !== "all" && { category }),
        ...(Pstatus === "show" && { show_on_homepage: true }),
        ...(Pstatus === "hide" && { show_on_homepage: false }),
      };

      const skip = (page - 1) * limit;

      const [products, total] = await Promise.all([
        productCollection
          .find(filterQuery)
          .sort({ createdAt: -1 })
          .skip(Number(skip))
          .limit(Number(limit))
          .toArray(),
        productCollection.countDocuments(filterQuery),
      ]);

      const formattedProducts = products.map((product) => ({
        _id: product._id,
        product_name: product.product_name,
        description: product.description,
        createdBy: product.createdByEmail,
        price: product.price,
        images: product.images,
        category: product.category,
        show_on_homepage: product.show_on_homepage || false,
        payment_Options:
          Array.isArray(product.payment_Options) ?
            product.payment_Options.join(" and ")
          : product.payment_Options,
        demo_video_link: product.demo_video_link,
        available_quantity: product.available_quantity,
      }));

      res.status(200).json({
        success: true,
        data: formattedProducts,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      });
    });

    app.get("/products/:id", async (req, res) => {
      const product = await productCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!product) {
        return res.status(404).json({ success: false });
      }

      const formattedProduct = {
        _id: product._id,
        product_name: product.product_name,
        description: product.description,
        price: product.price,
        images: Array.isArray(product.images) ? product.images : [],
        category: product.category,
        payment_Options:
          Array.isArray(product.payment_Options) ? product.payment_Options
          : typeof product.payment_Options === "string" ?
            product.payment_Options.split(",")
          : [],
        available_quantity: product.available_quantity,
        moq: product.moq,
        demo_video_link: product.demo_video_link,
      };

      res.json({
        success: true,
        data: formattedProduct,
      });
    });

    app.get(
      "/manage/products",
      verifyFBToken,
   
      async (req, res) => {
        const email = req.decoded_email;
        const products = await productCollection
          .find({ createdByEmail: email })
          .toArray();
        const formattedProducts = products.map((product) => ({
          ...product,
          payment_Options:
            Array.isArray(product.payment_Options) ?
              product.payment_Options.join(" and ")
            : product.payment_Options,
        }));
        res.status(200).json({
          success: true,
          data: formattedProducts,
        });
      },
    );

    app.put(
      "/products/:id",
      verifyFBToken,
     
      async (req, res) => {
        const { id } = req.params;
        const role = req.decoded_role;
        const email = req.decoded_email;
        const updateData = req.body;

        let filter = { _id: new ObjectId(id) };
        if (role === "user") {
          filter.createdByEmail = email;
        }

        const result = await productCollection.updateOne(filter, {
          $set: updateData,
        });

        const updatedProduct = await productCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).json({
          success: true,
          message: "Product updated successfully",
          data: updatedProduct,
        });
      },
    );

    app.delete(
      "/products/:id",
      verifyFBToken,
     
      async (req, res) => {
        const { id } = req.params;
        const role = req.decoded_role;
        const email = req.decoded_email;
        let filter = { _id: new ObjectId(id) };
        if (role === "user") {
          filter.createdByEmail = email;
        }

        const result = await productCollection.deleteOne(filter);
        res.json({ success: true });
      },
    );

    // ============ MY ORDERS ENDPOINTS ============

    app.get("/my-orders", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;
      const {
        searchText = "",
        page = 1,
        limit = 10,
        status = "all",
      } = req.query;

      let filterQuery = { CustomerEmail: email };

      if (searchText.trim()) {
        filterQuery.$or = [
          { orderId: { $regex: searchText, $options: "i" } },
          { "product.name": { $regex: searchText, $options: "i" } },
        ];
      }

      if (status !== "all") {
        filterQuery.status = status;
      }

      const skip = (page - 1) * limit;

      const total = await orderCollection.countDocuments(filterQuery);
      const orders = await orderCollection
        .find(filterQuery)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .toArray();

      res.json({
        success: true,
        data: orders,
        total,
        page: Number(page),
        totalPages: Math.ceil(total / limit),
      });
    });

    app.patch("/my-orders/cancel/:id", verifyFBToken, async (req, res) => {
      const { id } = req.params;
      const email = req.decoded_email;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: "Invalid ID" });
      }

      await orderCollection.updateOne(
        { _id: new ObjectId(id), CustomerEmail: email },
        {
          $set: {
            status: "cancelled",
            updatedAt: new Date(),
          },
        },
      );

      res.json({ success: true });
    });

    // ============ USER ENDPOINTS ============

    app.post("/users", async (req, res) => {
      try {
        const userInfo = req.body;

        // Check if user already exists
        const existingUser = await userCollection.findOne({
          email: userInfo.email,
        });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: "User already exists with this email",
          });
        }

        // Hash password with bcrypt if provided
        if (userInfo.password) {
          const salt = await bcrypt.genSalt(10);
          userInfo.password = await bcrypt.hash(userInfo.password, salt);
        }

        userInfo.createdAt = new Date();
        userInfo.status = "active";
        userInfo.updatedAt = new Date();
        userInfo.photoURL =
          userInfo.photoURL || "https://i.ibb.co/0jZqyvJ/user.png";

        const result = await userCollection.insertOne(userInfo);

        // Remove password from response
        const { password, ...userWithoutPassword } = userInfo;

        res.status(201).json({
          success: true,
          message: "User created successfully",
          inserted: true,
          data: {
            ...userWithoutPassword,
            _id: result.insertedId,
          },
        });
      } catch (error) {
        console.error("User creation error:", error);
        res.status(500).json({
          success: false,
          message: "Server error during user creation",
        });
      }
    });

    app.get("/users", verifyFBToken, async (req, res) => {
      const {
        page = 1,
        limit = 10,
        searchText = "",
        role = "all",
        status = "all",
      } = req.query;
      const pageNumber = parseInt(page);
      const pageSize = parseInt(limit);
      const skip = (pageNumber - 1) * pageSize;

      let filter = {};
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

      const transformedUsers = users.map((user) => ({
        ...user,
        photoURL: user.photoURL || "https://i.ibb.co/0jZqyvJ/user.png",
      }));

      res.status(200).json({
        success: true,
        data: transformedUsers,
        total,
        totalPages: Math.ceil(total / pageSize),
        currentPage: pageNumber,
        perPage: pageSize,
      });
    });

    app.get("/users/email/:email", async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne(
        { email: email },
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
    });

    app.patch(
      "/users/role/:id",
      verifyFBToken,
     
      async (req, res) => {
        const { id } = req.params;
        const { role } = req.body;

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } },
        );

        res.status(200).json({
          success: true,
          message: `User role updated to ${role}`,
        });
      },
    );

    app.patch(
      "/users/status/:id",
      verifyFBToken,
     
      async (req, res) => {
        const { id } = req.params;
        const { status, suspendReason = "", suspendFeedback = "" } = req.body;

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status,
              suspendReason,
              suspendFeedback,
              updatedAt: new Date(),
            },
          },
        );

        res.status(200).json({
          success: true,
          message: `User status updated to ${status}`,
        });
      },
    );

    // ============ PRODUCT HOMEPAGE TOGGLE ============

    app.patch(
      "/admin/products/show-on-home/:id",
      verifyFBToken,
      
      async (req, res) => {
        const { id } = req.params;
        const { show_on_homepage } = req.body;

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              show_on_homepage: show_on_homepage,
              updatedAt: new Date(),
            },
          },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Product not found",
          });
        }

        res.status(200).json({
          success: true,
          message:
            show_on_homepage ?
              "Product is now shown on home page"
            : "Product removed from home page",
          data: { show_on_homepage },
        });
      },
    );

    // ============ ADMIN ANALYTICS ============

    app.get(
      "/admin/analytics",
      verifyFBToken,
      
      async (req, res) => {
        const { range = "month" } = req.query;

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

        const analyticsData = {
          summary: {
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders,
            newCustomers: 0,
            productsSold: 0,
            avgOrderValue:
              totalOrders > 0 ? (totalRevenue[0]?.total || 0) / totalOrders : 0,
            conversionRate: 0,
          },
        };

        res.status(200).json({
          success: true,
          data: analyticsData,
          message: "Analytics data fetched successfully",
        });
      },
    );

    // ============ ORDER STATUS UPDATE ============

    app.put(
      "/orders/status/:id",
      verifyFBToken,
      verifyManager,
      async (req, res) => {
        const { id } = req.params;
        const { status, rejectionReason, approvedAt, rejectedAt } = req.body;

        if (!["approved", "rejected"].includes(status)) {
          return res.status(400).json({
            success: false,
            message: "Invalid status. Must be 'approved' or 'rejected'",
          });
        }

        const updateData = {
          status,
          updatedAt: new Date(),
        };

        if (status === "approved") {
          updateData.approvedAt =
            approvedAt ? new Date(approvedAt) : new Date();
        }

        if (status === "rejected") {
          updateData.rejectionReason = rejectionReason || "Rejected by manager";
          updateData.rejectedAt =
            rejectedAt ? new Date(rejectedAt) : new Date();
        }

        const result = await orderCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        const updatedOrder = await orderCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).json({
          success: true,
          message: `Order ${status} successfully`,
          data: updatedOrder,
        });
      },
    );

    // ============ TRACKING ENDPOINTS ============

    app.post(
      "/orders/tracking/:id",
      verifyFBToken,
    
      async (req, res) => {
        const { id } = req.params;
        const { location, note, status } = req.body;

        if (!location || !location.trim()) {
          return res.status(400).json({
            success: false,
            message: "Location is required",
          });
        }

        const order = await orderCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!order) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        const trackingEntry = {
          location,
          note: note || "",
          status: status || "Order Processing",
          dateTime: new Date(),
        };

        await trackingCollection.updateOne(
          { orderId: new ObjectId(id) },
          {
            $push: { history: trackingEntry },
            $set: { lastUpdated: new Date() },
          },
          { upsert: true },
        );

        res.status(200).json({
          success: true,
          message: "Tracking added successfully",
          data: trackingEntry,
        });
      },
    );

    app.get(
      "/orders",

      async (req, res) => {
        try {
          const { status, search, page = 1, limit = 10 } = req.query;

          const pageNumber = parseInt(page);
          const limitNumber = parseInt(limit);
          const skip = (pageNumber - 1) * limitNumber;

          let query = {};

          // ✅ Status Filter
          if (status && status !== "all") {
            query.status = status;
          }

          // ✅ Search Filter (Match YOUR DB Fields)
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
        } catch (error) {
          console.error("ORDER FETCH ERROR:", error);
          res.status(500).json({
            success: false,
            message: error.message,
          });
        }
      },
    );

    app.get(
      "/admin/orderTracking/:orderId",
      verifyFBToken,
    
      async (req, res) => {
        const { orderId } = req.params;

        const orderData = await orderCollection.findOne({
          $or: [{ _id: new ObjectId(orderId) }, { orderId }],
        });

        if (!orderData) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        const trackingDoc = await trackingCollection.findOne({
          orderId: orderData._id,
        });

        if (!trackingDoc) {
          return res.status(200).json({
            success: true,
            data: { order: orderData, timeline: [] },
            message: "No tracking history found",
          });
        }

        const timeline = trackingDoc.history.map((log, index) => ({
          id: index,
          step: log.status,
          Note: log.note || "No additional details",
          location: log.location || "Unknown",
          status:
            log.status === "product_delivered" ? "completed"
            : index === trackingDoc.history.length - 1 ? "current"
            : "completed",
          date: log.dateTime,
        }));

        const sortedTimeline = timeline.sort(
          (a, b) => new Date(b.date) - new Date(a.date),
        );

        res.status(200).json({
          success: true,
          data: { order: orderData, timeline: sortedTimeline },
          message: "Timeline fetched successfully",
        });
      },
    );

    app.get("/users/role/:email", async (req, res) => {
      const { email } = req.params;

      const user = await userCollection.findOne(
        { email: email },
        { projection: { password: 0 } },
      );

      if (!user) {
        return res.status(200).json({
          role: "buyer",
          exists: false,
        });
      }

      res.status(200).json({
        role: user?.role || "buyer",
        exists: true,
      });
    });

    app.get(
      "/track-order/timeline/:orderId",
      verifyFBToken,
      async (req, res) => {
        const { orderId } = req.params;

        const orderData = await orderCollection.findOne({
          $or: [{ _id: new ObjectId(orderId) }, { orderId }],
        });

        if (!orderData) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        const trackingDoc = await trackingCollection.findOne({
          orderId: orderData._id,
        });

        if (!trackingDoc) {
          return res.status(200).json({
            success: true,
            data: { order: orderData, timeline: [] },
            message: "No tracking history found",
          });
        }

        const timeline = trackingDoc.history.map((log, index) => ({
          id: index,
          step: log.status,
          Note: log.note || "No additional details",
          location: log.location || "Unknown",
          status:
            log.status === "product_delivered" ? "completed"
            : index === trackingDoc.history.length - 1 ? "current"
            : "completed",
          date: log.dateTime,
        }));

        const sortedTimeline = timeline.sort(
          (a, b) => new Date(b.date) - new Date(a.date),
        );

        res.status(200).json({
          success: true,
          data: { order: orderData, timeline: sortedTimeline },
          message: "Timeline fetched successfully",
        });
      },
    );

    // Send ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("My production tracker is running");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
