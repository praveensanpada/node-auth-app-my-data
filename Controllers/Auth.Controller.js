const createError = require('http-errors')
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require('../helpers/jwt_helper')
var conn = require('../helpers/init_mongodb');
var bcrypt = require('bcrypt');
var { compareSync } = require('bcrypt');
const emailvalidator = require("email-validator");
const validatePhoneNumber = require('validate-phone-number-node-js');
const crypto = require('crypto');
var custom_message = require("../custom/custom_message")
var custom_error = require("../custom/custom_error")
var ObjectId = require('mongodb').ObjectId;

module.exports = {

    // ---------------------------custom signup start-----------------------------

    signup: async (req, res, next) => {

        let {
            email,
            firstName,
            lastName,
            password,
            emailOtpKey,
            emailOtp
        } = req.body;

        if (email == undefined || email == null || email == "" || firstName == undefined || firstName == null || firstName == ""  || emailOtpKey == undefined || emailOtpKey == null || emailOtpKey == "" || emailOtp == undefined || emailOtp == null || emailOtp == "" || password == undefined || password == null || password == "") {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else if (!emailvalidator.validate(email)) {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.EMAIL_VALIDATION
            });
        } else {
            let user_email_check = await conn.collection('users').find({ email: email }).toArray();
            console.log(user_email_check)
            if (user_email_check.length > 0) {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    message: custom_message.EMAIL_FOUND
                });
            } else {
                let [hashValue, expires] = emailOtpKey.split(".");
                let now = new Date().getTime();
                if (now > parseInt(expires)) {
                    return res.status(500).json({
                        success: false,
                        status_code: custom_error.CODE_500,
                        status_msg: custom_error.MSG_500,
                        showUser: 1,
                        isEmailOtpExpired: 1,
                        message: custom_message.OTP_EXPIRE
                    });
                }
                let data1 = `${email}.${emailOtp}.${expires}`;
                let newCalculatedHash = crypto.createHmac("sha256", process.env.OTP_KEY).update(data1).digest("hex");
                if (newCalculatedHash === hashValue) {
                    let hashPass = await bcrypt.hash(password, 10);
                    let insertOne = await conn.collection('users').insertOne({
                        "email": email,
                        "phoneNumber": "",
                        "password": hashPass,
                        "isGoogleAccount": 0,
                        "firstName": firstName,
                        "lastName": lastName,
                        "countryCode": "",
                        "birthDate": "",
                        "isPhoneVerified": 0,
                        "isEmailVerified": 1,
                        "isUserBlocked": 0,
                        "userBlockReason": "",
                        "isKycDone": 0,
                        "bankProof": 0,
                        "governmentId": 0,
                    })
                    let myUuid = insertOne.ops[0]._id.toString();
                    const accessToken = await signAccessToken(myUuid)
                    const refreshToken = await signRefreshToken(myUuid)
                    return res.status(200).json({
                        success: true,
                        status_code: custom_error.CODE_200,
                        status_msg: custom_error.MSG_200,
                        showUser: 1,
                        isEmailOtpExpired: 0,
                        uuid: myUuid,
                        accessToken: accessToken,
                        refreshToken: refreshToken,
                        message: custom_message.USER_CREATED
                    });
                } else {
                    return res.status(500).json({
                        success: false,
                        status_code: custom_error.CODE_500,
                        status_msg: custom_error.MSG_500,
                        showUser: 1,
                        isEmailOtpExpired: 0,
                        message: custom_message.VERIFICATION_FAILED
                    });
                }
            }
        }
    },

    createEmailOtp: async (req, res, next) => {

        let {
            email,
        } = req.body;

        if (email == undefined || email == null || email == "") {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else if (emailvalidator.validate(email)) {
            const otp = Math.floor(1000 + Math.random() * 9000);
            const ttl = 60 * 60 * 1000;
            const expires = new Date().getTime() + ttl;
            const otpData = `${email}.${otp}.${expires}`;
            const hash = crypto.createHmac("sha256", process.env.OTP_KEY).update(otpData).digest("hex");
            const fullHash = `${hash}.${expires}`;
            return res.status(200).json({
                success: true,
                status_code: custom_error.CODE_200,
                status_msg: custom_error.MSG_200,
                showUser: 1,
                message: custom_message.OTP_SENT,
                response: {
                    emailOtpKey: fullHash,
                    emailOtp: otp
                }
            });
        } else {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.EMAIL_VALIDATION
            });
        }
    },

    createPhoneOtp: async (req, res, next) => {

        let {
            phoneNumber,
        } = req.body;

        if (phoneNumber == undefined || phoneNumber == null || phoneNumber == "") {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else if (validatePhoneNumber.validate(phoneNumber)) {
            const otp = Math.floor(1000 + Math.random() * 9000);
            const ttl = 60 * 60 * 1000;
            const expires = new Date().getTime() + ttl;
            const otpData = `${phoneNumber}.${otp}.${expires}`;
            const hash = crypto.createHmac("sha256", process.env.OTP_KEY).update(otpData).digest("hex");
            const fullHash = `${hash}.${expires}`;
            return res.status(200).json({
                success: true,
                status_code: custom_error.CODE_200,
                status_msg: custom_error.MSG_200,
                showUser: 1,
                message: custom_message.OTP_SENT,
                response: {
                    emailOtpKey: fullHash,
                    emailOtp: otp
                }
            });
        } else {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.PHONE_VALIDATION
            });
        }
    },

    verifyPhoneOtp: async (req, res, next) => {

        let {
            uuid,
            phoneNumber,
            phoneOtpKey,
            phoneOtp
        } = req.body;

        if (uuid == undefined || uuid == null || uuid == "" || phoneNumber == undefined || phoneNumber == null || phoneNumber == "" || phoneOtpKey == undefined || phoneOtpKey == null || phoneOtpKey == "" || phoneOtp == undefined || phoneOtp == null || phoneOtp == "") {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else if (validatePhoneNumber.validate(phoneNumber)) {
            let [hashValue, expires] = phoneOtpKey.split(".");
            let now = new Date().getTime();
            if (now > parseInt(expires)) {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    isPhoneOtpExpired: 1,
                    message: custom_message.OTP_EXPIRE
                });
            }
            let data1 = `${phoneNumber}.${phoneOtp}.${expires}`;
            let newCalculatedHash = crypto.createHmac("sha256", process.env.OTP_KEY).update(data1).digest("hex");
            if (newCalculatedHash === hashValue) {
                let myUuid = new ObjectId(uuid)
                let check_user = await conn.collection('users').findOne({ _id: !myUuid, phoneNumber: phoneNumber });
                if (check_user) {
                    return res.status(500).json({
                        success: false,
                        status_code: custom_error.CODE_500,
                        status_msg: custom_error.MSG_500,
                        showUser: 1,
                        message: custom_message.PHONE_FOUND
                    });
                } else {
                    const accessToken = await signAccessToken(uuid)
                    const refreshToken = await signRefreshToken(uuid)
                    let updateQuery = { _id: myUuid };
                    var updateQueryData = { $set: { phoneNumber: phoneNumber, isPhoneVerified: 1 } };
                    conn.collection('users').updateOne(updateQuery, updateQueryData, function (err, data) {
                        if (err) {
                            return res.status(500).json({
                                success: false,
                                status_code: custom_error.CODE_500,
                                status_msg: custom_error.MSG_500,
                                showUser: 1,
                                isPhoneOtpExpired: 0,
                                message: custom_message.DB_CONN_ERROR
                            });
                        } else {
                            return res.status(200).json({
                                success: true,
                                status_code: custom_error.CODE_200,
                                status_msg: custom_error.MSG_200,
                                showUser: 1,
                                accessToken: accessToken,
                                refreshToken: refreshToken,
                                isPhoneOtpExpired: 0,
                                message: custom_message.VERIFICATION_SUCCESS
                            });
                        }
                    })
                }
            } else {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    isPhoneOtpExpired: 0,
                    message: custom_message.VERIFICATION_FAILED
                });
            }
        } else {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.PHONE_VALIDATION
            });
        }
    },

    //--------------------------------custom-signup-end------------------------

    // -----------------------------custom login start-------------------------------

    login: async (req, res, next) => {

        let {
            email,
            password,
        } = req.body;

        if (email == undefined || email == null || email == "" || password == undefined || password == null || password == "") {
            return res.status(500).json({
                success: false,
                status_code: 500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else if (!emailvalidator.validate(email)) {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.EMAIL_VALIDATION
            });
        } else {
            let user_email_check = await conn.collection('users').findOne({ email: email });
            if (user_email_check.isEmailVerified == 0) {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    message: custom_message.EMAIL_NOT_VERIFY
                });
            } else if (user_email_check.email == email) {
                const check_pass = await compareSync(password, user_email_check.password);
                if (check_pass) {
                    let myUuid = user_email_check._id.toString();
                    const otp = Math.floor(1000 + Math.random() * 9000);
                    const ttl = 60 * 60 * 1000;
                    const expires = new Date().getTime() + ttl;
                    const otpData = `${email}.${otp}.${expires}`;
                    const hash = crypto.createHmac("sha256", process.env.OTP_KEY).update(otpData).digest("hex");
                    const fullHash = `${hash}.${expires}`;
                    return res.status(200).json({
                        success: true,
                        status_code: custom_error.CODE_200,
                        status_msg: custom_error.MSG_200,
                        uuid: myUuid,
                        email: "*****" + email.slice(-15),
                        isPhoneVerified: user_email_check.isPhoneVerified,
                        emailOtpKey: fullHash,
                        emailOtp: otp,
                        message: custom_message.USER_LOGIN
                    });
                } else {
                    return res.status(500).json({
                        success: false,
                        status_code: custom_error.CODE_500,
                        status_msg: custom_error.MSG_500,
                        showUser: 1,
                        message: custom_message.WRONG_PASSWORD
                    });
                }
            } else {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    message: custom_message.EMAIL_NOT_FOUND
                });
            }
        }
    },

    verifyUser: async (req, res, next) => {

        let {
            email,
            emailOtpKey,
            emailOtp
        } = req.body;

        if (email == undefined || email == null || email == "" || emailOtpKey == undefined || emailOtpKey == null || emailOtpKey == "" || emailOtp == undefined || emailOtp == null || emailOtp == "") {
            return res.status(500).json({
                success: false,
                status_code: custom_error.CODE_500,
                status_msg: custom_error.MSG_500,
                showUser: 1,
                message: custom_message.BODY_MISSING_PARAMS
            });
        } else {
            let [hashValue, expires] = emailOtpKey.split(".");
            let now = new Date().getTime();
            if (now > parseInt(expires)) {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    isEmailOtpExpired: 1,
                    message: custom_message.OTP_EXPIRE
                });
            }
            let data1 = `${email}.${emailOtp}.${expires}`;
            let newCalculatedHash = crypto.createHmac("sha256", process.env.OTP_KEY).update(data1).digest("hex");
            if (newCalculatedHash === hashValue) {
                let user_email_check = await conn.collection('users').findOne({ email: email });
                let myUuid = user_email_check._id.toString();
                const accessToken = await signAccessToken(myUuid)
                const refreshToken = await signRefreshToken(myUuid)
                return res.status(200).json({
                    success: true,
                    status_code: custom_error.CODE_200,
                    status_msg: custom_error.MSG_200,
                    showUser: 1,
                    firstName: user_email_check.firstName,
                    lastName: user_email_check.lastName,
                    isUserBlocked: user_email_check.isUserBlocked,
                    isEmailOtpExpired: 0,
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    message: custom_message.VERIFICATION_SUCCESS
                });
            } else {
                return res.status(500).json({
                    success: false,
                    status_code: custom_error.CODE_500,
                    status_msg: custom_error.MSG_500,
                    showUser: 1,
                    isEmailOtpExpired: 0,
                    message: custom_message.VERIFICATION_FAILED
                });
            }
        }
    },


    // --------------------------------------custom login end--------------------

    getData: async (req, res, next) => {
        try {
            conn.collection('users').find().toArray(async (err, data) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        status_code: custom_error.CODE_500,
                        status_msg: custom_error.MSG_500,
                        showUser: 1,
                        message: custom_message.DB_CONN_ERROR
                    });
                } else {
                    if (data.length > 0) {
                        return res.status(200).json({
                            success: true,
                            status_code: custom_error.CODE_200,
                            status_msg: custom_error.MSG_200,
                            response: data,
                            message: custom_message.USER_FETCHED
                        });
                    } else {
                        return res.status(500).json({
                            success: false,
                            status_code: custom_error.CODE_500,
                            status_msg: custom_error.MSG_500,
                            showUser: 1,
                            message: custom_message.USER_NOT_EXIT
                        });
                    }
                }
            });
        } catch (error) {
            console.log(error)
        }
    },
}
