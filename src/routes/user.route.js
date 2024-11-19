const express = require("express");

const router = express.Router();
const userController = require("../controllers/user.controller");

const validateUserId = (req, res, next) => {
    const userId = parseInt(req.params.id);
    if (isNaN(userId) || userId <= 0) {
        return res.status(400).json({ message: "Invalid user ID" });
    }
    next();
};

router.get("/", validateUserId, userController.getAllUsers);
router.get("/:id", validateUserId, userController.getUserById);
router.post("POST /", validateUserId, userController.createUser);
router.put("PUT /:Id", validateUserId, userController.updateUser);
router.delete("/:id", validateUserId, userController.deleteUser);

module.exports = router;