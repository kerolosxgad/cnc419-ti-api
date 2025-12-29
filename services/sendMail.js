require('dotenv').config();
const axios = require('axios');

const sendMail = async (to, subject, html) => {
    const { MAILGUN_DOMAIN, MAILGUN_SEND_KEY } = process.env;

    const formData = new FormData();
    formData.append('from', `CNC419 TI Project <noreply@${MAILGUN_DOMAIN}>`);
    formData.append('to', to);
    formData.append('subject', subject);
    formData.append('html', html);

    try {
        const response = await axios.post(
            `https://api.eu.mailgun.net/v3/${MAILGUN_DOMAIN}/messages`,
            formData,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                auth: {
                    username: 'api',
                    password: MAILGUN_SEND_KEY
                }
            }
        );
        return { success: true, data: response.data };
    } catch (error) {
        console.error('Error sending email:', error.response.data);
        return { success: false, error: error.response.data };
    }
};

module.exports = { sendMail };
