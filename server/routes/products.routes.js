const express = require("express");
const { ObjectId } = require("mongodb");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");

const formatProduct = (product) => ({
  _id: product._id,
  product_name: product.product_name,
  description: product.description,
  createdBy: product.createdByEmail,
  price: product.price,
  images: Array.isArray(product.images) ? product.images : [],
  category: product.category,
  show_on_homepage: Boolean(product.show_on_homepage),
  payment_Options: Array.isArray(product.payment_Options)
    ? product.payment_Options
    : typeof product.payment_Options === "string"
      ? product.payment_Options.split(",")
      : [],
  demo_video_link: product.demo_video_link,
  available_quantity: product.available_quantity,
  moq: product.moq,
});

const productsRoutes = ({ collections, authenticate, authorizeRoles }) => {
  const router = express.Router();
  const { productCollection } = collections;

  router.post(
    "/products",
    authenticate,
    asyncHandler(async (req, res) => {
      const product = {
        ...req.body,
        createdByEmail: req.user.email,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const result = await productCollection.insertOne(product);
      res.status(201).json({
        success: true,
        message: "Product created successfully",
        data: { ...product, _id: result.insertedId },
      });
    }),
  );

  router.get(
    "/products",
    asyncHandler(async (req, res) => {
      const {
        searchText = "",
        page = 1,
        limit = 10,
        category = "all",
        Pstatus = "all",
        sortBy = "createdAt",
        sortOrder = "desc",
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
        ...(Pstatus === "show" && { show_on_homepage: true }),
        ...(Pstatus === "hide" && { show_on_homepage: false }),
      };

      const pageNumber = Number(page);
      const pageSize = Number(limit);
      const skip = (pageNumber - 1) * pageSize;
      const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

      const [products, total] = await Promise.all([
        productCollection
          .find(filterQuery)
          .sort(sort)
          .skip(skip)
          .limit(pageSize)
          .toArray(),
        productCollection.countDocuments(filterQuery),
      ]);

      res.status(200).json({
        success: true,
        data: products.map(formatProduct),
        total,
        page: pageNumber,
        totalPages: Math.ceil(total / pageSize),
        limit: pageSize,
      });
    }),
  );

  router.get(
    "/products/:id",
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid product ID");
      const product = await productCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      if (!product) throw new ApiError(404, "Product not found");

      res.status(200).json({ success: true, data: formatProduct(product) });
    }),
  );

  router.get(
    "/manage/products",
    authenticate,
    asyncHandler(async (req, res) => {
      const query =
        req.user.role === "admin" || req.user.role === "manager"
          ? {}
          : { createdByEmail: req.user.email };
      const products = await productCollection.find(query).toArray();
      res.status(200).json({ success: true, data: products.map(formatProduct) });
    }),
  );

  router.put(
    "/products/:id",
    authenticate,
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid product ID");
      const filter = { _id: new ObjectId(req.params.id) };
      if (!["admin", "manager"].includes(req.user.role)) {
        filter.createdByEmail = req.user.email;
      }

      const updateData = { ...req.body, updatedAt: new Date() };
      const result = await productCollection.updateOne(filter, { $set: updateData });
      if (!result.matchedCount) throw new ApiError(404, "Product not found");

      const updatedProduct = await productCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      res.status(200).json({
        success: true,
        message: "Product updated successfully",
        data: updatedProduct,
      });
    }),
  );

  router.delete(
    "/products/:id",
    authenticate,
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid product ID");
      const filter = { _id: new ObjectId(req.params.id) };
      if (!["admin", "manager"].includes(req.user.role)) {
        filter.createdByEmail = req.user.email;
      }

      const result = await productCollection.deleteOne(filter);
      if (!result.deletedCount) throw new ApiError(404, "Product not found");
      res.json({ success: true, message: "Product deleted successfully" });
    }),
  );

  router.patch(
    "/admin/products/show-on-home/:id",
    authenticate,
    authorizeRoles("admin", "manager"),
    asyncHandler(async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) throw new ApiError(400, "Invalid product ID");
      const { show_on_homepage } = req.body;
      const result = await productCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { show_on_homepage: Boolean(show_on_homepage), updatedAt: new Date() } },
      );

      if (!result.matchedCount) throw new ApiError(404, "Product not found");
      res.status(200).json({
        success: true,
        message: show_on_homepage
          ? "Product is now shown on home page"
          : "Product removed from home page",
        data: { show_on_homepage: Boolean(show_on_homepage) },
      });
    }),
  );

  return router;
};

module.exports = productsRoutes;
