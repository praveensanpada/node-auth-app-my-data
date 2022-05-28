const express = require('express')
const router = express.Router()
const AuthController = require('../Controllers/Auth.Controller')

router.post('/signup', AuthController.signup)

router.post('/login', AuthController.login)

router.post('/send-email-otp', AuthController.createEmailOtp)

router.post('/refresh-token', AuthController.refreshToken)

router.delete('/logout', AuthController.logout)

router.get('/get-data', AuthController.getData)

module.exports = router
