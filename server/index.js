require("dotenv").config();
const createApp = require("./app");

const port = process.env.PORT || 3000;

const bootstrap = async () => {
  const app = await createApp();
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
};

bootstrap().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
