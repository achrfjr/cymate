
import nodemailer from 'nodemailer'
import dotenv from 'dotenv'

dotenv.config()

export default class EmailSender {
    /**
   * Sends an email with a dynamic subject and tool result as content.
   * @param {string} userEmail - The recipient's email address.
   * @param {string} subject - The email subject (e.g., name of the tool).
   * @param {string} toolResult - The result/output of the security tool.
   */
    constructor() {}

    async sendEmail(userMail, subject, toolResult) {
        try {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            })

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: userMail,
                subject: subject,
                text: toolResult,
            }

            const info = await transporter.sendMail(mailOptions)
            console.log('Email sent:', info.response)
        }
    catch (error) {   
        console.error('Error sending email:', error)
        throw new Error('Failed to send email')
        }
    }
}