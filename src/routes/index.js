const express = require("express");
const imageRoute = require("./image.route");

const router = express.Router();

router.use("/images", imageRoute);

module.exports = router;