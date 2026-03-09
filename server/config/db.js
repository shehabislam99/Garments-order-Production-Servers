const { MongoClient, ServerApiVersion } = require("mongodb");

let client;
let collections;

const getMongoUri = () => {
  if (process.env.MONGO_URI) return process.env.MONGO_URI;
  return `mongodb+srv://${process.env.Db_USERNAME}:${process.env.Db_Password}@cluster0.pealo3m.mongodb.net/?appName=Cluster0`;
};

const connectDB = async () => {
  if (collections) return collections;

  client = new MongoClient(getMongoUri(), {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  await client.connect();

  const db = client.db(process.env.DB_NAME || "Garments_production");
  collections = {
    userCollection: db.collection("user"),
    productCollection: db.collection("products"),
    orderCollection: db.collection("orders"),
    paymentCollection: db.collection("payment"),
    trackingCollection: db.collection("tracking"),
    contactMessageCollection: db.collection("contactMessages"),
  };

  return collections;
};

module.exports = {
  connectDB,
};
