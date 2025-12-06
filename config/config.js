require('dotenv').config();

module.exports = {
  [process.env.SEQUELIZE_ENV || 'development']: {
    username: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    host:     process.env.DB_HOST,
    port:     process.env.DB_PORT || 3306,
    dialect:  process.env.DB_DIALECT
  }
};
