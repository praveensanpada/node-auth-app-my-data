

const accountSID = process.env.TWILLIO_ACCOUNT_SID
const authToken = process.env.TWILLIO_AUTH_TOKEN
const twilioPhoneNumber = process.env.TWILLIO_PHONE_NUMBER

// const sgMail = require('@sendgrid/mail');

const clientMessage = require('twilio')(accountSID, authToken);


function sendPhoneOtpMessage(phoneNumber, phoneOtp, phoneOtpKey) {

    clientMessage.messages
        .create({
            body: 'Hi, Nomoexian. Your phone otp is ' + phoneOtp + ' and phone otp key is ' + phoneOtpKey + '.',
            from: twilioPhoneNumber,
            to: '+919142238690'
        })
        .then(message => console.log(message.sid));

}


// function sendEmailOtpMessage(email, emailOtp, emailOtpKey) {

//     sgMail.setApiKey(process.env.EMAIL_SENDGRID_API_KEY);
//     const msg = {
//         to: email,
//         from: process.env.MY_EMAIL_FOR_OTP,
//         subject: 'OTP for Nomoex App',
//         text: 'Hi, Nomoexian.',
//         html: 'Your email otp is ' + emailOtp + ' and email otp key is ' + emailOtpKey + '.',
//     };
//     sgMail.send(msg);

// }



module.exports = {
    sendPhoneOtpMessage: sendPhoneOtpMessage
}



