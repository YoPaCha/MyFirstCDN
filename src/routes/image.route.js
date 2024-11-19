const express = require("express");
const multer = require("multer");
const path = require("path");

const router = express.Router();
const imageController = require("../controllers/image.controller");

// Set up storage for uploaded images
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'data/images/'); // Specify the destination folder for uploads
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext); // Create a unique filename
    }
});

// Initialize multer with the storage configuration
const upload = multer({ storage: storage });

router.get("/", imageController.getAllImages);
router.get("/:id", imageController.getImageById);
router.get("/userId/:id", imageController.getImagesByUserId);
router.post("/upload", upload.single('image'), imageController.uploadImage);
router.delete("/:id", imageController.deleteImage);

module.exports = router;