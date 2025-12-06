const sequelize = require("sequelize");
const path = require("path");
const fs = require("fs");
const { User } = require("../models/user");
const FormData = require("form-data");
const axios = require("axios");

// User Controllers
const getUser = async (req, res) => {
  try {
    const { username } = req.body;

    // Check if the username already exists in the database
    const user = await User.findOne({ where: { username } });

    // Validate required fields
    if (!username) {
      return res.status(400).json({ message_en: "Username is required", message_ar: "اسم المستخدم مطلوب" });
    }

    // Check if the user is authorized to get the user data
    if (!user) {
      return res.status(404).json({ message_en: "User not found", message_ar: "المستخدم غير موجود" });
    }

    // Retrieve user data from users table, excluding password, otp, and id
    const userData = await User.findOne({
      where: { username },
      attributes: {
        exclude: [
          "id",
          "email",
          "dialCode",
          "phone",
          "nationalId",
          "password",
          "otp",
          "tokenVersion",
          "status",
          "updatedAt",
        ],
      },
    });

    return res
      .status(200)
      .json({ message_en: "User found", message_ar: "تم العثور على المستخدم", userData: userData });
  } catch (error) {
    console.error("Error during user update:", error);
    return res.status(500).json({ message_en: "Internal server error", message_ar: "خطأ داخلي في الخادم" });
  }
};

const updateUser = async (req, res) => {
  try {
    const {
      username,
      newUsername,
      fullName,
      bio,
      countryCode,
      dialCode,
      phone,
    } = req.body;

    const user = await User.findOne({ where: { username } });

    // Check if the user is authorized to update the user data
    if (req.user.sub === user.id) {
      if (!user) {
        return res.status(404).json({ message_en: "User not found", message_ar: "المستخدم غير موجود" });
      }

      // Check if the user is active
      if (user.status !== "active") {
        return res.status(401).json({ message_en: "User is not active", message_ar: "المستخدم غير نشط" });
      }

      // If newUsername is provided, validate and check uniqueness
      if (newUsername !== undefined && newUsername !== username) {
        // Validate newUsername format (no spaces, no special chars, alphanumeric + dots only)
        const usernameRegex = /^[a-zA-Z0-9.]+$/;
        if (
          !newUsername ||
          typeof newUsername !== "string" ||
          newUsername.length < 3 ||
          !usernameRegex.test(newUsername)
        ) {
          return res.status(400).json({
            message_en: "Username must contain only letters, numbers, and dots, without spaces or special characters",
            message_ar: "اسم المستخدم يجب أن يحتوي على أحرف وأرقام ونقاط فقط، بدون مسافات أو رموز خاصة",
          });
        }
        const existingUser = await User.findOne({
          where: { username: newUsername },
        });
        if (existingUser) {
          return res
            .status(400)
            .json({ message_en: "New username is already in use", message_ar: "اسم المستخدم الجديد مستخدم بالفعل" });
        }
        user.username = newUsername;
      }

      // Validate country code format (2 uppercase letters)
      const countryCodeRegex = /^[A-Z]{2}$/;
      if (countryCode !== undefined && !countryCodeRegex.test(countryCode)) {
        return res.status(400).json({
          message_en: "Invalid country code format. It should be 2 uppercase letters.",
          message_ar: "تنسيق رمز البلد غير صحيح. يجب أن يكون حرفين كبيرين.",
        });
      }

      // Validate dial code format (e.g., +1, +91)
      const dialCodeRegex = /^\+\d{1,4}$/;
      if (dialCode !== undefined && !dialCodeRegex.test(dialCode)) {
        return res.status(400).json({
          message_en: "Invalid dial code format. It should start with + followed by 1 to 4 digits.",
          message_ar: "تنسيق رمز الاتصال غير صحيح. يجب أن يبدأ بـ + متبوعًا بـ 1 إلى 4 أرقام.",
        });
      }

      // Validate phone number format (4 to 15 digits)
      const phoneRegex = /^[1-9]\d{3,14}$/;
      if (phone !== undefined && !phoneRegex.test(phone)) {
        return res.status(400).json({
          message_en: "Invalid phone number format. It should be between 4 to 15 digits and not start with 0",
          message_ar: "تنسيق رقم الهاتف غير صحيح. يجب أن يكون بين 4 إلى 15 رقمًا ولا يبدأ بـ 0",
        });
      }

      // Check if the phone number is being changed
      if (phone !== undefined && user.phone !== phone) {
        const existingPhone = await User.findOne({ where: { phone } });
        if (existingPhone) {
          return res.status(400).json({ message_en: "Phone number is already in use", message_ar: "رقم الهاتف مستخدم بالفعل" });
        }
        user.phone = phone;
      }

      // Update the user's data in the database only if new values are provided
      if (fullName !== undefined) user.fullName = fullName;
      if (bio !== undefined) user.bio = bio;
      if (countryCode !== undefined) user.countryCode = countryCode;
      if (dialCode !== undefined) user.dialCode = dialCode;

      // Save the updated user data
      await user.save();

      return res
        .status(200)
        .json({ message_en: "User data updated successfully", message_ar: "تم تحديث بيانات المستخدم بنجاح" });
    } else {
      return res.status(401).json({ message_en: "Unauthorized", message_ar: "غير مصرح" });
    }
  } catch (error) {
    console.error("Error during user update:", error);
    return res.status(500).json({ message_en: "Internal server error", message_ar: "خطأ داخلي في الخادم" });
  }
};

const updateImage = async (req, res) => {
  try {
    const { username } = req.body;

    const image = req.file ? req.file.filename : null;

    // Validate required fields
    if (!username || !image) {
      return res
        .status(400)
        .json({ message_en: "Please fill all required fields correctly", message_ar: "يرجى ملء جميع الحقول المطلوبة بشكل صحيح" });
    }

    // Check if the username already exists in the database
    const user = await User.findOne({ where: { username } });

    if (!user) {
      return res.status(404).json({ message_en: "User not found", message_ar: "المستخدم غير موجود" });
    }

    // Validate image size not exceeding 5MB
    const imagePath = path.join(__dirname, "../uploads", image);
    try {
      const stats = fs.statSync(imagePath);
      const fileSizeInMB = stats.size / (1024 * 1024);
      if (fileSizeInMB > 5) {
        return res.status(400).json({
          message_en: "Image size is too large. It should be less than 5 megabytes",
          message_ar: "حجم الصورة كبير جداً. يجب أن يكون أقل من 5 ميجابايت",
        });
      }
    } catch (fileError) {
      return res.status(400).json({
        message_en: "Error reading image file",
        message_ar: "خطأ في قراءة ملف الصورة",
      });
    }

    // Check if the user is authorized to change the profile image
    if (req.user.sub === user.id) {
      // check if the user is active
      if (user.status !== "active") {
        return res.status(401).json({ message_en: "User is not active", message_ar: "المستخدم غير نشط" });
      }

      // Update the user's profile image
      user.image = image;
      await user.save();

      return res
        .status(200)
        .json({ message_en: "Profile image updated successfully", message_ar: "تم تحديث صورة الملف الشخصي بنجاح" });
    } else {
      return res.status(401).json({ message_en: "Unauthorized", message_ar: "غير مصرح" });
    }
  } catch (error) {
    console.error("Error during profile image update:", error);
    return res.status(500).json({ message_en: "Internal server error", message_ar: "خطأ داخلي في الخادم" });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ message_en: "Username is required", message_ar: "اسم المستخدم مطلوب" });
    }

    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ message_en: "User not found", message_ar: "المستخدم غير موجود" });
    }

    if (req.user.sub !== user.id) {
      return res.status(401).json({ message_en: "Unauthorized", message_ar: "غير مصرح" });
    }

    if (user.status !== "active") {
      return res.status(401).json({ message_en: "User is not active", message_ar: "المستخدم غير نشط" });
    }

    // Remove applications made by the user
    await Application.destroy({ where: { userId: user.id } });

    // Remove resumes of the user
    await Resume.destroy({ where: { userId: user.id } });

    // If the user is a company, remove their opportunities and related applications
    const isCompany = user.role === "company";

    if (isCompany) {
      // Find all opportunity ids for this company
      const oppRows = await Opportunity.findAll({
        where: { companyId: user.id },
        attributes: ["id"],
      });
      const oppIds = oppRows.map((o) =>
        o.get ? o.get({ plain: true }).id : o.id
      );

      // Delete applications for those opportunities
      if (oppIds.length > 0) {
        await Application.destroy({
          where: { opportunityId: { [sequelize.Op.in]: oppIds } },
        });
      }

      // Delete the opportunities themselves
      await Opportunity.destroy({ where: { companyId: user.id } });
    }

    // Remove user
    await user.destroy();

    return res.status(200).json({ message_en: "User deleted successfully", message_ar: "تم حذف المستخدم بنجاح" });
  } catch (error) {
    console.error("Error deleting user:", error);
    return res.status(500).json({ message_en: "Internal server error", message_ar: "خطأ داخلي في الخادم" });
  }
};

module.exports = {
  getUser,
  updateUser,
  updateImage,
  deleteUser
};
