import nodemailer from 'nodemailer';
import dotenv from 'dotenv'

dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.MAILTRAP_USER,
    pass: process.env.MAILTRAP_PASS,
  },
});

export async function sendMail(to: string, subject: string, text: string) {
  console.log(process.env.MAILTRAP_USER, process.env.MAILTRAP_PASS)
  await transporter.sendMail({
    from: '"Candidate - Harli Fauzi Ramli" <no-reply@harleykwen.com>',
    to,
    subject,
    text,
  });
}

