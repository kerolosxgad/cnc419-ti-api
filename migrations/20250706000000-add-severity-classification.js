'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Add severity column
    await queryInterface.addColumn('ThreatIndicators', 'severity', {
      type: Sequelize.ENUM('critical', 'high', 'medium', 'low', 'info'),
      allowNull: false,
      defaultValue: 'medium',
      after: 'raw'
    });

    // Add confidence column if it doesn't exist
    try {
      await queryInterface.addColumn('ThreatIndicators', 'confidence', {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 50,
        after: 'severity'
      });
    } catch (error) {
      // Column might already exist, ignore error
      console.log('Confidence column might already exist, skipping...');
    }

    // Add tags column if it doesn't exist
    try {
      await queryInterface.addColumn('ThreatIndicators', 'tags', {
        type: Sequelize.JSON,
        allowNull: true,
        defaultValue: [],
        after: 'confidence'
      });
    } catch (error) {
      // Column might already exist, ignore error
      console.log('Tags column might already exist, skipping...');
    }

    // Add index on severity for faster queries
    await queryInterface.addIndex('ThreatIndicators', ['severity'], {
      name: 'idx_severity'
    });

    // Add composite index for severity and type queries
    await queryInterface.addIndex('ThreatIndicators', ['severity', 'type'], {
      name: 'idx_severity_type'
    });

    // Add index on confidence
    await queryInterface.addIndex('ThreatIndicators', ['confidence'], {
      name: 'idx_confidence'
    });
  },

  down: async (queryInterface, Sequelize) => {
    // Remove indexes
    await queryInterface.removeIndex('ThreatIndicators', 'idx_severity');
    await queryInterface.removeIndex('ThreatIndicators', 'idx_severity_type');
    await queryInterface.removeIndex('ThreatIndicators', 'idx_confidence');

    // Remove columns
    await queryInterface.removeColumn('ThreatIndicators', 'tags');
    await queryInterface.removeColumn('ThreatIndicators', 'confidence');
    await queryInterface.removeColumn('ThreatIndicators', 'severity');
  }
};
