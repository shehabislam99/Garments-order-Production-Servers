require("dotenv").config();
const createApp = require("./app");

const port = process.env.PORT || 3000;

let appPromise;

const getAppPromise = () => {
  if (!appPromise) {
    appPromise = createApp();
  }
  return appPromise;
};

const bootstrap = async () => {
  const app = await getAppPromise();
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
};

const handler = async (req, res) => {
  const app = await getAppPromise();
  return app(req, res);
};

if (require.main === module) {
  bootstrap().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
}

module.exports = handler;
