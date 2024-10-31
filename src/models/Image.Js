const mongoose = require('mongoose');

const imageSchema = new mongoose.Schema({
    link: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true}
});

const Image = mongoose.model('Image', imageSchema);
module.exports = Image;