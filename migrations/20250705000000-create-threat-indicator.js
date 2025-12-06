'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('ThreatIndicators', {
      id: {
        type: Sequelize.BIGINT.UNSIGNED,
        autoIncrement: true,
        primaryKey: true,
        allowNull: false,
      },
      type: {
        type: Sequelize.STRING(32),
        allowNull: false,
      },
      value: {
        type: Sequelize.STRING(512),
        allowNull: false,
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true,
      },
      source: {
        type: Sequelize.STRING(512),
        allowNull: true,
      },
      fingerprint: {
        type: Sequelize.STRING(64),
        allowNull: false,
        unique: true,
      },
      observedCount: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 1,
      },
      firstSeen: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      lastSeen: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      raw: {
        type: Sequelize.JSON,
        allowNull: true,
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'),
      }
    });

    // Add indexes
    await queryInterface.addIndex('ThreatIndicators', ['fingerprint'], {
      unique: true,
      name: 'idx_fingerprint'
    });

    await queryInterface.addIndex('ThreatIndicators', ['type'], {
      name: 'idx_type'
    });

    await queryInterface.addIndex('ThreatIndicators', ['value'], {
      name: 'idx_value'
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('ThreatIndicators');
  }
};
