const sequelize = require("sequelize");
const bcrypt = require("bcrypt");
const { User } = require("../models/user");

// User Management Endpoints
const getUser = async (req, res) => {
  try {
    const { username, email, id } = req.body;

    // Validate required fields
    if (!username && !email && !id) {
      return res.status(400).json({
        message: "يرجى تحديد اسم المستخدم أو البريد الإلكتروني بشكل صحيح",
      });
    }

    // Find the user by username or email
    // Build where clause based on provided fields
    let whereClause = {};
    if (id) {
      whereClause.id = id;
    }
    if (username) {
      whereClause.username = username;
    }
    if (email) {
      whereClause.email = email;
    }

    const user = await User.findOne({
      where: whereClause,
    });
    if (!user) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    // Retrieve user data, excluding sensitive fields
    const userData = await User.findOne({
      where: whereClause,
      attributes: {
        exclude: ["id", "password", "otp", "tokenVersion", "updatedAt"],
      },
    });

    return res
      .status(200)
      .json({ message: "تم العثور على المستخدم", userData });
  } catch (error) {
    console.error("Error getting user:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const editRole = async (req, res) => {
  try {
    const { username, role } = req.body;

    // Validate required fields
    if (!username || !role) {
      return res
        .status(400)
        .json({ message: "يرجى تحديد اسم المستخدم والدور بشكل صحيح" });
    }

    // Validate role
    const validRoles = ["admin", "user"];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ message: "الدور المحدد غير صالح" });
    }

    // Find the user by username
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    // Invalidate tokens by incrementing tokenVersion if the new role is different than the old one
    if (user.role !== role) {
      await User.increment({ tokenVersion: 1 }, { where: { id: user.id } });

      // Update the user's role
      user.role = role;
    }

    // Save the updated user data
    await user.save();

    return res.status(200).json({ message: "تم تحديث دور المستخدم بنجاح" });
  } catch (error) {
    console.error("Error editing user role:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const editStatus = async (req, res) => {
  try {
    const { username, status } = req.body;

    // Validate required fields
    if (!username || !status) {
      return res
        .status(400)
        .json({ message: "يرجى تحديد اسم المستخدم والحالة بشكل صحيح" });
    }
    // Validate status
    const validStatuses = ["active", "inactive"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "الحالة المحددة غير صالحة" });
    }

    // Find the user by username
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    // Invalidate tokens by incrementing tokenVersion if the new status is different than the old one
    if (user.status !== status) {
      await User.increment({ tokenVersion: 1 }, { where: { id: user.id } });

      // Update the user's status
      user.status = status;
    }

    // Save the updated user data
    await user.save();

    return res.status(200).json({ message: "تم تحديث حالة المستخدم بنجاح" });
  } catch (error) {
    console.error("Error editing user status:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const listUsers = async (req, res) => {
  const DEFAULT_LIMIT = 20;

  // Parse query params
  const hasPage = typeof req.query.page !== "undefined";
  const hasLimit = typeof req.query.limit !== "undefined";
  const { search, type, status, isBanned, countryCode, order } = req.query;

  // Build where clause based on filters
  let where = {};
  if (type === "admins") {
    where.role = "admin";
  } else if (type === "users") {
    where.role = "user";
  }
  if (status) where.status = status;
  if (isBanned === "true") where.isBanned = true;
  if (countryCode) where.countryCode = countryCode;
  if (search && search.trim() !== "") {
    where[sequelize.Op.or] = [
      { username: { [sequelize.Op.like]: `%${search.trim()}%` } },
      { email: { [sequelize.Op.like]: `%${search.trim()}%` } },
      { fullName: { [sequelize.Op.like]: `%${search.trim()}%` } },
      { phone: { [sequelize.Op.like]: `%${search.trim()}%` } },
    ];
  }

  // Order direction
  const orderDirection =
    order && order.toUpperCase() === "ASC" ? "ASC" : "DESC";

  let users, count, page, limit, offset;

  try {
    if (!hasPage && !hasLimit) {
      // No pagination: return all users
      users = await User.findAll({
        where,
        attributes: [
          "id",
          "username",
          "fullName",
          "email",
          "countryCode",
          "dialCode",
          "phone",
          "dateOfBirth",
          "gamesCredit",
          "role",
          "status",
          "isBanned",
          "createdAt",
        ],
        order: [["createdAt", orderDirection]],
      });
      count = users.length;
      page = 1;
      limit = count;
      offset = 0;
    } else {
      // With pagination
      page = Math.max(parseInt(req.query.page) || 1, 1);
      limit = Math.min(parseInt(req.query.limit) || DEFAULT_LIMIT, 100);
      offset = (page - 1) * limit;

      const result = await User.findAndCountAll({
        where,
        attributes: [
          "id",
          "username",
          "fullName",
          "email",
          "countryCode",
          "dialCode",
          "phone",
          "dateOfBirth",
          "gamesCredit",
          "role",
          "status",
          "isBanned",
          "createdAt",
        ],
        order: [["createdAt", orderDirection]],
        limit,
        offset,
      });
      users = result.rows;
      count = result.count;
    }

    // For each user, get totalPaidCredits
    const usersWithCredits = await Promise.all(
      users.map(async (user) => {
        const totalPaidCredits = await Payment.sum("credits", {
          where: { userId: user.id, status: "paid" },
        });
        const totalCouponCredits = await CouponRedemption.sum("credits", {
          where: { userId: user.id },
        });
        return {
          ...user.toJSON(),
          totalPaidCredits: totalPaidCredits || 0,
          totalCouponCredits: totalCouponCredits || 0,
        };
      })
    );

    // Respond with data and simple pagination meta
    return res.status(200).json({
      data: usersWithCredits,
      meta: {
        totalItems: count,
        totalPages: hasPage || hasLimit ? Math.ceil(count / (limit || 1)) : 1,
        currentPage: hasPage ? page : 1,
        pageSize: hasLimit ? limit : count,
        hasNext: hasPage && hasLimit ? page * limit < count : false,
        hasPrev: hasPage ? page > 1 : false,
      },
    });
  } catch (error) {
    console.error("Error listing users:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports = {
  getUser,
  editRole,
  editStatus,
  listUsers
};
