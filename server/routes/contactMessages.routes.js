const express = require("express");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");

const contactMessagesRoutes = ({ collections }) => {
  const router = express.Router();
  const { contactMessageCollection } = collections;

  router.post(
    "/contact-messages",
    asyncHandler(async (req, res) => {
      const { name, email, phone, subject, message } = req.body || {};

      if (!name?.trim()) throw new ApiError(400, "Name is required");
      if (!email?.trim()) throw new ApiError(400, "Email is required");
      if (!message?.trim()) throw new ApiError(400, "Message is required");

      const contactMessage = {
        name: name.trim(),
        email: email.trim(),
        phone: phone?.trim() || "",
        subject: subject?.trim() || "",
        message: message.trim(),
        createdAt: new Date(),
      };

      const result = await contactMessageCollection.insertOne(contactMessage);

      res.status(201).json({
        success: true,
        message: "Message submitted successfully",
        data: { ...contactMessage, _id: result.insertedId },
      });
    }),
  );

  return router;
};

module.exports = contactMessagesRoutes;
