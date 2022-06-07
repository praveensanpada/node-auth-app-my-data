const express = require('express')
const router = express.Router()
const AuthController = require('../Controllers/Auth.Controller')

const { verifyAccessToken } = require('../helpers/jwt_helper')

router.post('/signup', AuthController.signup)

router.post('/login', AuthController.login)

router.post('/send-email-otp', AuthController.createEmailOtp)

router.post('/verify-email-otp', AuthController.verifyEmailOtp)

router.post('/send-phone-otp', verifyAccessToken, AuthController.createPhoneOtp)

router.post('/verify-phone-otp', verifyAccessToken, AuthController.verifyPhoneOtp)

router.post('/reset', verifyAccessToken, AuthController.reset)

router.post('/refresh-token', AuthController.refreshToken)

router.post('/forgot-password', AuthController.forgotPassword)

router.post('/forgot-password2', AuthController.forgotPassword2)

router.delete('/logout', AuthController.logout)

router.get('/get-data', AuthController.getData)

module.exports = router
