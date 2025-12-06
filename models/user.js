const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

// Define the User model with profile fields
const User = sequelize.define("User", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
    allowNull: false,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  countryCode: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      is: /^[A-Z]{2}$/, // basic country code validation
    },
  },
  dialCode: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      is: /^\+\d{1,4}$/, // basic dial code validation
    },
  },
  phone: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      is: /^[1-9]\d{3,14}$/, // phone number must not start with 0, 4-15 digits
    },
  },
  dateOfBirth: {
    type: DataTypes.DATEONLY,
    allowNull: true, // optional field
  },
  gender: {
    type: DataTypes.ENUM("male", "female"),
    allowNull: true, // optional field
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  otp: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  tokenVersion: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
  },
  role: {
    type: DataTypes.ENUM("admin", "user"),
    defaultValue: "user",
    allowNull: false,
  },
  image: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  status: {
    type: DataTypes.ENUM("active", "inactive"),
    defaultValue: "inactive",
    allowNull: false,
  },
  isBanned: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
  },
});

// Sync the User model to the database
(async () => {
  try {
    await User.sync();
    console.log("User model was synchronized successfully.");
  } catch (error) {
    console.error("Error synchronizing model:", error);
  }
})();

module.exports = { User };
