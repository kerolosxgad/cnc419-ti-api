require('dotenv').config();
const bcrypt = require('bcrypt');

'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    // Hash the password before seeding
    const passwordHash = await bcrypt.hash(process.env.ADMIN_PASS, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await queryInterface.bulkInsert('Users', [{
      username: 'userADMIN',
      firstName: 'Super',
      lastName: 'Admin',
      email: 'admin@codextech.org',
      countryCode: 'EG',
      dialCode: '+20',
      phone: '1066953497',
      dateOfBirth: '2003-07-26',
      gender: 'male',
      password: passwordHash,
      otp: otp,
      tokenVersion: 0,
      role: 'admin',
      status: 'active',
      isBanned: false,
      createdAt: new Date(),
      updatedAt: new Date()
    }], {});
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('Users', { username: 'userADMIN' }, {});
  }
};
