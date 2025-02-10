const Order = require("../models/Order");
const crypto = require('crypto');

// Define your encryption/decryption key (you should store this in an environment variable)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // 32-byte key (e.g., a random string)
const IV_LENGTH = 16; // Initialization vector length

// Encrypt function
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH); // Generate random IV
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Returning IV and encrypted text together
}

// Decrypt function
function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

exports.create = async (req, res) => {
    try {
        // Encrypt sensitive fields before saving the order
        const encryptedPaymentDetails = encrypt(req.body.paymentDetails);
        const encryptedAddress = encrypt(req.body.address);

        const created = new Order({
            ...req.body,
            paymentDetails: encryptedPaymentDetails,
            address: encryptedAddress
        });

        await created.save();
        res.status(201).json(created);
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: 'Error creating an order, please try again later' });
    }
};

exports.getByUserId = async (req, res) => {
    try {
        const { id } = req.params;
        const results = await Order.find({ user: id });

        // Decrypt sensitive fields before sending the response
        const decryptedResults = results.map(order => {
            return {
                ...order.toObject(),
                paymentDetails: decrypt(order.paymentDetails),
                address: decrypt(order.address)
            };
        });

        res.status(200).json(decryptedResults);
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: 'Error fetching orders, please try again later' });
    }
};

exports.getAll = async (req, res) => {
    try {
        let skip = 0;
        let limit = 0;

        if (req.query.page && req.query.limit) {
            const pageSize = req.query.limit;
            const page = req.query.page;
            skip = pageSize * (page - 1);
            limit = pageSize;
        }

        const totalDocs = await Order.find({}).countDocuments().exec();
        const results = await Order.find({}).skip(skip).limit(limit).exec();

        // Decrypt sensitive fields before sending the response
        const decryptedResults = results.map(order => {
            return {
                ...order.toObject(),
                paymentDetails: decrypt(order.paymentDetails),
                address: decrypt(order.address)
            };
        });

        res.header("X-Total-Count", totalDocs);
        res.status(200).json(decryptedResults);
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error fetching orders, please try again later' });
    }
};

exports.updateById = async (req, res) => {
    try {
        const { id } = req.params;

        // Encrypt sensitive fields before updating the order
        const encryptedPaymentDetails = encrypt(req.body.paymentDetails);
        const encryptedAddress = encrypt(req.body.address);

        const updated = await Order.findByIdAndUpdate(
            id,
            {
                ...req.body,
                paymentDetails: encryptedPaymentDetails,
                address: encryptedAddress
            },
            { new: true }
        );

        res.status(200).json(updated);
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error updating order, please try again later' });
    }
};
