const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3000;
const crypto = require("crypto");

//keyConverter
const admin = require("firebase-admin");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
); 
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//middleware
app.use(express.json());
app.use(cors());

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

    // verifyFBToken middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);

      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }

      next();
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
    const verifyAdminOrManager = async (req, res, next) => {
      const email = req.decoded_email;

      const user = await userCollection.findOne({ email });

      if (user?.role === "admin" || user?.role === "manager") {
        return next();
      }

      return res.status(403).json({
        success: false,
        message: "Forbidden access",
      });
    };



    // payment related api
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
        }
      );

      res.json({
        success: true,
        transactionId: session.payment_intent,
        trackingId,
        amount: session.amount_total / 100,
      });
    });

    //Profile
app.get("/profile", verifyFBToken, async (req, res) => {

    const email = req.decoded_email;
    const user = await userCollection.findOne({ email });
    
    const { password, ...userData } = user;

    res.status(200).json({
      success: true,
      data: userData,
    });

  
});


    //tracking ID genarated
    const generateTrackingId = () => {
      const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const random = crypto.randomBytes(3).toString("hex").toUpperCase();
      return `TRK${timestamp}${random}`;
    };

    // POST (orders  and  payment  api)
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

    app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
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
    // show on home
    app.patch(
      "/admin/products/show-on-home/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { showOnHome } = req.body;

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { showOnHome: showOnHome, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Product not found",
          });
        }

        res.status(200).json({
          success: true,
          message: showOnHome
            ? "Product is now shown on home page"
            : "Product removed from home page",
          data: { showOnHome },
        });
      }
    );
    //  Update product
    app.put(
      "/products/:id",
      verifyFBToken,
      verifyAdminOrManager,
      async (req, res) => {
        const { id } = req.params;
        const updateData = req.body;
        const filteredUpdateData = {
          name: updateData.name,
          description: updateData.description || "",
          price: parseFloat(updateData.price),
          category: updateData.category,
          images: updateData.images || [],
          demoVideo: updateData.demoVideo || "",
          paymentOptions: updateData.paymentOptions || [],
          updatedAt: new Date(),
        };

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: filteredUpdateData }
        );

        const updatedProduct = await productCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).json({
          success: true,
          message: "Product updated successfully",
          data: updatedProduct,
        });
      }
    );
    // Delete product
    app.delete(
      "/products/:id",
      verifyFBToken,
      verifyAdminOrManager,
      async (req, res) => {
        await productCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ success: true });
      }
    );

  
    app.get(
      "/manager/stats",
      verifyFBToken,
      verifyManager,
      async (req, res) => {
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
      }
    );

    //DashBoard  buyer all api
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
    // Get Buyer orders with pagination and filters
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
    // Cancel Buyer order - Fixed endpoint path to match frontend expectation
    app.patch("/my-orders/cancel/:id", verifyFBToken, async (req, res) => {
      const { id } = req.params;
      const email = req.decoded_email;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: "Invalid ID" });
      }

      const order = await orderCollection.findOne({
        _id: new ObjectId(id),
        CustomerEmail: email,
      });


      await orderCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "cancelled",
            updatedAt: new Date(),
          },
        }
      );

      res.json({ success: true });
    });

    
    //user post in database
    app.post("/users", async (req, res) => {
      const userInfo = req.body;
      userInfo.createdAt = new Date();
      userInfo.status = "pending";

      const result = await userCollection.insertOne(userInfo);
      res.status(201).send({
        message: "User created successfully",
        inserted: true,
        result,
      });
    });

    //user get in frontend
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

      res.status(200).json({
        success: true,
        data: users,
        total,
        totalPages: Math.ceil(total / pageSize),
        currentPage: pageNumber,
        perPage: pageSize,
      });
    });

    //   STATS MANAGEMENT WITH FILTERS, PAGINATION IN FRONTEND FRONTEND (FULL DATABASE)
    app.get("/users/stats", verifyFBToken, async (req, res) => {
      const stats = await userCollection
        .aggregate([
          {
            $facet: {
              totalUsers: [{ $count: "count" }],

              roles: [
                {
                  $addFields: {
                    roleField: { $ifNull: ["$role", "buyer"] },
                  },
                },
                {
                  $group: {
                    _id: "$roleField",
                    count: { $sum: 1 },
                  },
                },
              ],

              statuses: [
                {
                  $addFields: {
                    statusField: { $ifNull: ["$status", "pending"] },
                  },
                },
                {
                  $group: {
                    _id: "$statusField",
                    count: { $sum: 1 },
                  },
                },
              ],
            },
          },
        ])
        .toArray();

      const result = stats[0] || {};

      const roleCounts = {
        admin: 0,
        manager: 0,
        buyer: 0,
      };

      const statusCounts = {
        active: 0,
        suspended: 0,
        pending: 0,
      };
      if (result.roles && Array.isArray(result.roles)) {
        result.roles.forEach((r) => {
          const role = r._id;
          if (role && roleCounts.hasOwnProperty(role)) {
            roleCounts[role] = r.count;
          }
        });
      }

      if (result.statuses && Array.isArray(result.statuses)) {
        result.statuses.forEach((s) => {
          const status = s._id;
          if (status && statusCounts.hasOwnProperty(status)) {
            statusCounts[status] = s.count;
          }
        });
      }

      res.status(200).json({
        success: true,
        totalUsers: result.totalUsers?.[0]?.count || 0,
        roles: roleCounts,
        statuses: statusCounts,
      });
    });

    //Role update in frontend
    app.patch(
      "/users/role/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { role } = req.body;
       await userCollection.findOne({ _id: new ObjectId(id) });

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );

        res.status(200).json({
          success: true,
          message: `User role updated to ${role}`,
          modifiedCount: 1,
        });
      }
    );

    //user status suspend and approve in frontend
    app.patch(
      "/users/status/:id",
      verifyFBToken,
      verifyAdmin,
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
          }
        );

        res.status(200).json({
          success: true,
          message: `User status updated to ${status}`,
        });
      }
    );

    // ADMIN ANALYTICS WITH FILTERS IN FRONTEND
    app.get(
      "/admin/analytics",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { range = "month" } = req.query;
        let days;
        switch (range) {
          case "week":
            days = 7;
            break;
          case "month":
            days = 30;
            break;
          case "quarter":
            days = 90;
            break;
          case "year":
            days = 365;
            break;
          default:
            days = 30;
        }

        const [totalOrders, totalProducts, totalRevenue] = await Promise.all([
          orderCollection.countDocuments({}),
          productCollection.countDocuments({}),
          // Calculate total revenue from orders
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
            totalOrders: totalOrders,
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
      }
    );

    app.post("/products", async (req, res) => {
      const product = req.body;
      const newProduct = {
        ...product,
        createdAt: new Date(),
      };
      const result = await productCollection.insertOne(newProduct);
      res.send(result);
      console.log("Product data:", req.body);
      res.json({
        success: true,
        message: "Product received",
        data: req.body,
      });
    });


    // PRODUCT WITH FILTERS, PAGINATION IN FRONTEND
    app.get("/products", async (req, res) => {
      const {
        searchText = "",
        page = 1,
        limit = 10,
        category = "all",
        status = "all",
      } = req.query;

      const filterQuery = {
        ...(searchText && {
          $or: [
            { product_name: { $regex: searchText, $options: "i" } },
            { description: { $regex: searchText, $options: "i" } },
            { category: { $regex: searchText, $options: "i" } },
          ],
        }),
        ...(category !== "all" && { category }),
        ...(status === "show" && { showOnHome: true }),
        ...(status === "hide" && { showOnHome: false }),
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
        createdBy: product.createdByEmail,
        price: product.price,
        images: product.images,
        category: product.category,
        showOnHome: product.showOnHome || false,
        payment_Options: product.payment_Options,
        demo_video_link: product.demo_video_link,
        available_quantity: product.available_quantity,
      }));

      res.status(200).json({
        success: true,
        data: formattedProducts,
        total: total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      });
    });

    // get single product
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
        payment_Options: Array.isArray(product.payment_Options)
          ? product.payment_Options
          : typeof product.payment_Options === "string"
          ? product.payment_Options.split(",")
          : [],
        available_quantity: product.available_quantity,
        moq: product.moq,
      };

      res.json({
        success: true,
        data: formattedProduct,
      });
    });

   
app.put("/orders/status/:id",verifyFBToken,verifyManager, async (req, res) => {
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
      updateData.approvedAt = approvedAt ? new Date(approvedAt) : new Date();
    }

    if (status === "rejected") {
      updateData.rejectionReason = rejectionReason || "Rejected by manager";
      updateData.rejectedAt = rejectedAt ? new Date(rejectedAt) : new Date();
    }

  

    const result = await orderCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
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


  
});
      
      
  app.post(
    "/orders/:id/tracking",
    verifyFBToken,
    verifyAdminOrManager,
    async (req, res) => {
        const { id } = req.params;
        const { location, note, status, dateTime } = req.body;
      const trackingId = generateTrackingId();
        product.trackingId = trackingId;

        logTracking(trackingId, "product_created");
        // 1. Validation
        if (!location || !location.trim()) {
          return res.status(400).json({
            success: false,
            message: "Location is required",
          });
        }

        // 2. Check if the order exists
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
          dateTime: dateTime ? new Date(dateTime) : new Date(),
          addedAt: new Date(),
        };

       
        const result = await trackingCollection.updateOne(
          { orderId: new ObjectId(id) }, 
          {
            $push: { history: trackingEntry },
            $set: { lastUpdated: new Date() },
          },
          { upsert: true }
        );

        res.status(200).json({
          success: true,
          message: "Tracking update added successfully",
          data: trackingEntry,
        });
  
    }
  );
   


    app.get(
      "/orders",
      verifyFBToken,
      verifyAdminOrManager,
      async (req, res) => {
          const { status, search, page = 1, limit = 10 } = req.query;
          const skip = (parseInt(page) - 1) * parseInt(limit);

          let query = {};
          if (status && status !== "all") {
            query.status = status;
          }

          if (search && search.trim()) {
            const searchRegex = new RegExp(search, "i");
            query.$or = [
              { orderId: searchRegex },
              { trackingId: searchRegex },
              { "user.name": searchRegex },
              { "user.email": searchRegex },
              { "items.name": searchRegex },
            ];
          }

          const [orders, total] = await Promise.all([
            orderCollection
              .find(query)
              .sort({ createdAt: -1 })
              .skip(skip)
              .limit(parseInt(limit))
              .toArray(),
            orderCollection.countDocuments(query),
          ]);

          res.status(200).json({
            success: true,
            data: orders,
            total,
            page: parseInt(page),
            totalPages: Math.ceil(total / parseInt(limit)),
            limit: parseInt(limit),
          });
       
      }
    );

    //get product stats
    app.get("/products/stats", verifyFBToken, async (req, res) => {
      const [totalProducts, showOnHomeCount] = await Promise.all([
        productCollection.countDocuments({}),
        productCollection.countDocuments({ showOnHome: true }),
      ]);

      const productsByCategory = await productCollection
        .aggregate([
          {
            $group: {
              _id: { $ifNull: ["$category", "Uncategorized"] },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      const categoriesObj = {};
      productsByCategory.forEach((cat) => {
        const categoryName = cat._id;
        categoriesObj[categoryName] = cat.count;
      });

      const responseData = {
        totalProducts: totalProducts,
        categories: categoriesObj,
        showOnHome: showOnHomeCount,
        hiddenFromHome: totalProducts - showOnHomeCount,
      };

      res.status(200).json({
        success: true,
        data: responseData,
        message: "Product statistics fetched successfully",
      });
    });

    app.patch(
      "/admin/orders/status/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { status } = req.body;
        const validStatuses = [
          "pending",
          "approved",
          "rejected",
          "delivered",
          "cancelled",
        ];

        const result = await orderCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: status,
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        res.status(200).json({
          success: true,
          message: `Order status updated to ${status}`,
          data: { status },
        });
      }
    );

    // Add a GET endpoint for fetching role (better for AuthProvider)
    app.get("/users/role/:email", async (req, res) => {
      const { email } = req.params;

      const user = await userCollection.findOne({ email: email });

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

    app.get("/products/order", async (req, res) => {
      const { orderEmail, deliveryStatus } = req.query;
      const query = {};

      if (orderEmail) {
        query.orderEmail = orderEmail;
      }
      if (deliveryStatus !== "product_delivered") {
        query.deliveryStatus = { $nin: ["product_delivered"] };
      } else {
        query.deliveryStatus = deliveryStatus;
      }

      const cursor = productCollection.find(query);
      const result = await cursor.toArray();
      res.send(result);
    });

  

    app.patch("/products/status/:id", async (req, res) => {
      const { deliveryStatus, orderId, trackingId } = req.body;

      const query = { _id: new ObjectId(req.params.id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: deliveryStatus,
        },
      };

      if (deliveryStatus === "product_delivered") {
        const orderQuery = { _id: new ObjectId(orderId) };
        const orderUpdatedDoc = {
          $set: {
            workStatus: "available",
          },
        };
        const orderResult = await orderCollection.updateOne(
          orderQuery,
          orderUpdatedDoc
        );
      }

      const result = await productCollection.updateOne(query, updatedDoc);
      logTracking(trackingId, deliveryStatus);

      res.send(result);
    });

  
app.get("/track-order/:orderId/timeline", verifyFBToken, async (req, res) => {
  const { orderId } = req.params;

  try {
    const trackingDoc = await trackingCollection.findOne({
      orderId: new ObjectId(orderId),
    });

    if (!trackingDoc) {
      return res.status(404).json({
        success: false,
        message: "No tracking history found for this order",
      });
    }

    // Map the history to match frontend expectations
    const timeline = trackingDoc.history.map((log, index) => ({
      id: index,
      step: log.status,
      description: log.note || "No additional details",
      location: log.location || "Unknown",
      status:
        log.status === "product_delivered"
          ? "completed"
          : index === 0 // First item is most recent
          ? "current"
          : "completed",
      date: log.dateTime, // Use dateTime field from database
    }));

    // Reverse to show newest first
    timeline.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.status(200).json({
      success: true,
      data: timeline,
      message: "Timeline fetched successfully",
    });
  } catch (error) {
    console.error("Error fetching timeline:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch tracking timeline",
    });
  }
});
   

   // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    
  } finally {
    // Ensures that the client will close when you finish/error
    //     await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("My production tracker is running");
});

app.listen(port, () => {
  
});
