const sharp = require('sharp');
const path = require("path");
const fs = require('fs');

const imageSizes = [
    { suffix: 'small', width: 300, height: 300 },
    { suffix: 'medium', width: 600, height: 600 },
    { suffix: 'large', width: 1200, height: 1200 }
];

const imageFormats = ['webp', 'jpeg', 'png'];

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

exports.uploadImage = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        let { userId } = req.body;

        // Validate userId
        if (!userId) {
            userId = 1; 
        }

        const originalImagePath = req.file.path;
        const originalFileName = path.basename(originalImagePath);
        const originalExtension = path.extname(originalFileName);

        console.log(`File uploaded: ${originalFileName}, MIME type: ${req.file.mimetype}`);

        // Ensure the file is a valid image
        if (!['image/jpeg', 'image/png', 'image/webp'].includes(req.file.mimetype)) {
            return res.status(400).json({ message: "Invalid image format. Please upload a JPEG, PNG, or WebP image." });
        }

        const optimizedImages = [];

        // Generate resized and optimized images
        for (const size of imageSizes) {
            for (const format of imageFormats) {
                const optimizedImageName = `${Date.now()}-${size.suffix}-${format}.${format}`;
                const optimizedImagePath = path.join('data/images/optimized', optimizedImageName);

                let image = sharp(originalImagePath).resize(size.width, size.height);

                // Apply quality only for formats that support it
                if (format === 'jpeg' || format === 'webp') {
                    image = image.toFormat(format).quality(80);  // Apply compression for JPEG and WebP
                } else {
                    image = image.toFormat(format);  // PNG doesn't need quality adjustment
                }

                await image.toFile(optimizedImagePath);

                optimizedImages.push({
                    size: size.suffix,
                    format,
                    path: optimizedImagePath,
                });
            }
        }

        const newImage = {
            id: Date.now(),
            link: req.file.path,
            userId,
            uploadedAt: new Date(),
            optimizedImages: optimizedImages
        };

        images.push(newImage);

        res.status(201).json(newImage);
    } catch (error) {
        res.status(500).json({ message: "Error uploading and optimizing image", error: error.message });
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