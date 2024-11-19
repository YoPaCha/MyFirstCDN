const path = require("path");

const images = [];

exports.getAllImages = (req, res) => {
    try {
        res.status(200).json(images);
    } catch (error) {
        res.status(500).json({ message: "Error fetching images", error: error.message });
    }
};

exports.getImageById = (req, res) => {
    try {
        const imageId = parseInt(req.params.id);

        const image = images.find(img => img.id === imageId);

        if (!image) {
            return res.status(404).json({ message: "Image not found" });
        }

        res.status(200).json(image);
    } catch (error) {
        res.status(500).json({ message: "Error fetching image", error: error.message });
    }
};

exports.getImagesByUserId = (req, res) => {
    try {
        const userId = req.params.userId;

        const userImages = images.filter(img => img.userId === userId);

        if (userImages.length === 0) {
            return res.status(404).json({ message: "No images found for this user" });
        }

        res.status(200).json(userImages);
    } catch (error) {
        res.status(500).json({ message: "Error fetching images by user ID", error: error.message });
    }
};

exports.uploadImage = (req, res) => {
    try {
        let { userId } = req.body;

        // Validate userId
        if (!userId) {
            userId = 1; 
            //return res.status(400).json({ message: "User ID is required" });
        }

        const newImage = {
            id: Date.now(),
            link: req.file.path,
            userId,
            uploadedAt: new Date()
        };

        images.push(newImage);

        res.status(201).json(newImage);
    } catch (error) {
        res.status(500).json({ message: "Error uploading image", error: error.message });
    }
};

exports.deleteImage = (req, res) => {
    try {
        const imageId = parseInt(req.params.id);

        const index = images.findIndex(img => img.id === imageId);

        if (index === -1) {
            return res.status(404).json({ message: "Image not found" });
        }

        images.splice(index, 1);

        res.status(200).json({ message: "Image deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting image", error: error.message });
    }
};