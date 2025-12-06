const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

// Define the ThreatIndicator model with necessary fields
const ThreatIndicator = sequelize.define(
   'ThreatIndicator',
  {
    id: {
      type: DataTypes.BIGINT.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
      allowNull: false,
    },
    type: {
      type: DataTypes.STRING(32),
      allowNull: false, // ip | domain | hash | url ...
    },
    value: {
      type: DataTypes.STRING(512),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    source: {
      type: DataTypes.STRING(512),
      allowNull: true,
    },
    fingerprint: {
      type: DataTypes.STRING(64),
      allowNull: false,
      unique: true, // sha256 hex
    },
    observedCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
      defaultValue: 1,
    },
    firstSeen: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    lastSeen: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    raw: {
      type: DataTypes.JSON,
      allowNull: true,
    },
    severity: {
      type: DataTypes.ENUM('critical', 'high', 'medium', 'low', 'info'),
      allowNull: false,
      defaultValue: 'medium',
    },
    confidence: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
      defaultValue: 50,
      validate: {
        min: 0,
        max: 100
      }
    },
    tags: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: []
    }
  },
  {
    indexes: [
      { unique: true, fields: ["fingerprint"] },
      { fields: ["type"] },
      { fields: ["value"] },
    ],
  }
);

(async () => {
  try {
    await ThreatIndicator.sync();
    console.log("Threat Indicator model was synchronized successfully.");
  } catch (error) {
    console.error("Error synchronizing ThreatIndicator model:", error);
  }
})();

module.exports = { ThreatIndicator };
