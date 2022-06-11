const express = require('express')
const router = express.Router()
const AuthController = require('../Controllers/Auth.Controller')
const { verifyAccessToken } = require("../helpers/jwt_helper")

router.post('/signup', AuthController.signup)
router.post('/send-email-otp', AuthController.createEmailOtp)
router.post('/send-phone-otp', AuthController.createPhoneOtp)
router.post('/verify-phone-otp', AuthController.verifyPhoneOtp)

router.post('/login', AuthController.login)
router.post('/verify-user', AuthController.verifyUser)

router.get('/get-data', AuthController.getData)


module.exports = router
