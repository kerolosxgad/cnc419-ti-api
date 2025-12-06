const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

// Define the Log model with necessary fields
const Log = sequelize.define('Log', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
        allowNull: false
    },
    level: {
      type: DataTypes.STRING,
      defaultValue: 'info',
    },
    message: {
      type: DataTypes.TEXT,
    }
});

// Sync the Log model to the database
(async () => {
    try {
        await Log.sync();
        console.log("Log model was synchronized successfully.");
    } catch (error) {
        console.error("Error synchronizing model:", error);
    }
})();

module.exports = { Log };
