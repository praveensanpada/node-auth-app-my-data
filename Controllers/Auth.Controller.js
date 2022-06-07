const createError = require('http-errors')
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../helpers/jwt_helper')
const client = require('../helpers/init_redis')
var conn = require('../helpers/init_mongodb');
var bcrypt = require('bcrypt');
var { compareSync } = require('bcrypt');
const emailvalidator = require("email-validator");
const validatePhoneNumber = require('validate-phone-number-node-js');
const crypto = require('crypto');
var custom_message = require("../custom/custom_message")
var custom_error = require("../custom/custom_error")

module.exports = {

  signup: async (req, res, next) => {

    let {
      email,
      phoneNumber,
      firstName,
      lastName,
      password,
      emailOtpKey,
      otp
    } = req.body;

    if (email == undefined || email == null || email == "" || firstName == undefined || firstName == null || firstName == "" || lastName == undefined || lastName == null || lastName == "" || emailOtpKey == undefined || emailOtpKey == null || emailOtpKey == "" || otp == undefined || otp == null || otp == "" || password == undefined || password == null || password == "") {
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
    } else if (!validatePhoneNumber.validate(phoneNumber)) {
      return res.status(500).json({
        success: false,
        status_code: custom_error.CODE_500,
        status_msg: custom_error.MSG_500,
        showUser: 1,
        message: custom_message.PHONE_VALIDATION
      });
    } else {
      let user_email_check = await conn.collection('users').find({ $or: [{ email: email }, { phoneNumber: phoneNumber }] }).toArray();
      if (user_email_check.length > 0) {
        return res.status(500).json({
          success: false,
          status_code: custom_error.CODE_500,
          status_msg: custom_error.MSG_500,
          showUser: 1,
          message: custom_message.EMAIL_PHONE_NOT_FOUND
        });
      } else {

        let [hashValue, expires] = emailOtpKey.split(".");
        const OTP_KEY = "pnc1234"
        let now = new Date().getTime();
        if (now > parseInt(expires)) {
          const otp = Math.floor(1000 + Math.random() * 9000);
          const ttl = 60 * 60 * 1000;
          const expires = new Date().getTime() + ttl;
          const data1 = `${email}.${otp}.${expires}`;
          const OTP_KEY = "pnc1234"
          const hash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
          const fullHash = `${hash}.${expires}`;
          return res.status(200).json({
            success: true,
            status_code: custom_error.CODE_200,
            status_msg: custom_error.MSG_200,
            showUser: 1,
            message: custom_message.OTP_SENT,
            response: {
              emailOtpKey: fullHash,
              otp: otp
            }
          });
        }
        let data1 = `${email}.${otp}.${expires}`;
        let newCalculatedHash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
        if (newCalculatedHash === hashValue) {

          let hashPass = await bcrypt.hash(password, 10);
          let insertOne = await conn.collection('users').insertOne({
            "email": email,
            "phoneNumber": phoneNumber,
            "password": hashPass,
            "isGoogleAccount": 0,
            "firstName": firstName,
            "lastName": lastName,
            "countryCode": "+91",
            "birthDate": "15/07/1998",
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
          res.setHeader("refreshToken", myUuid)
          res.setHeader("accessToken", accessToken);
          return res.status(200).json({
            success: true,
            status_code: custom_error.CODE_200,
            status_msg: custom_error.MSG_200,
            showUser: 1,
            uuid: myUuid,
            message: custom_message.USER_CREATED
          });
        } else {
          return res.status(500).json({
            success: false,
            status_code: custom_error.CODE_500,
            status_msg: custom_error.MSG_500,
            showUser: 1,
            message: custom_message.VERIFICATION_FAILED
          });
        }
      }
    }
  },

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
      if (user_email_check) {
        const check_pass = await compareSync(password, user_email_check.password);
        if (check_pass) {
          let myUuid = user_email_check._id.toString();
          const accessToken = await signAccessToken(myUuid)
          const refreshToken = await signRefreshToken(myUuid)
          res.setHeader("refreshToken", myUuid)
          res.setHeader("accessToken", accessToken);
          return res.status(200).json({
            success: true,
            status_code: custom_error.CODE_200,
            status_msg: custom_error.MSG_200,
            uuid: myUuid,
            email: "*****" + email.slice(-15),
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

  refreshToken: async (req, res, next) => {
    try {
      const { refreshToken } = req.body
      if (!refreshToken) throw createError.BadRequest()
      const userId = await verifyRefreshToken(refreshToken)

      const accessToken = await signAccessToken(userId)
      const refToken = await signRefreshToken(userId)
      res.send({ accessToken: accessToken, refreshToken: refToken })
    } catch (error) {
      next(error)
    }
  },

  logout: async (req, res, next) => {
    try {
      const { refreshToken } = req.body
      console.log(refreshToken)
      if (!refreshToken) throw createError.BadRequest()
      const userId = await verifyRefreshToken(refreshToken)
      client.DEL(userId, (err, val) => {
        if (err) {
          console.log(err.message)
          throw createError.InternalServerError()
        }
        return res.status(200).json({
          success: true,
          status_code: custom_error.CODE_200,
          status_msg: custom_error.MSG_200,
          showUser: 1,
          message: custom_message.USER_LOGOUT
        });
      })
    } catch (error) {
      next(error)
    }
  },

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
      const OTP_KEY = "pnc1234"
      const hash = crypto.createHmac("sha256", OTP_KEY).update(otpData).digest("hex");
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

  verifyEmailOtp: async (req, res, next) => {

    let {
      email,
      emailOtpKey,
      otp
    } = req.body;

    let [hashValue, expires] = emailOtpKey.split(".");
    const OTP_KEY = "pnc1234"
    let now = new Date().getTime();
    if (now > parseInt(expires)) {
      const otp = Math.floor(1000 + Math.random() * 9000);
      const ttl = 60 * 60 * 1000;
      const expires = new Date().getTime() + ttl;
      const data1 = `${email}.${otp}.${expires}`;
      const OTP_KEY = "pnc1234"
      const hash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
      const fullHash = `${hash}.${expires}`;
      return res.status(200).json({
        success: true,
        status_code: custom_error.CODE_200,
        status_msg: custom_error.MSG_200,
        showUser: 1,
        message: custom_message.OTP_SENT,
        response: {
          emailOtpKey: fullHash,
          otp: otp
        }
      });
    }
    let data1 = `${email}.${otp}.${expires}`;
    let newCalculatedHash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
    if (newCalculatedHash === hashValue) {
      return res.status(200).json({
        success: true,
        status_code: custom_error.CODE_200,
        status_msg: custom_error.MSG_200,
        showUser: 1,
        message: custom_message.VERIFICATION_SUCCESS
      });
    } else {
      return res.status(500).json({
        success: false,
        status_code: custom_error.CODE_500,
        status_msg: custom_error.MSG_500,
        showUser: 1,
        message: custom_message.VERIFICATION_FAILED
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
      let user_phone_check = await conn.collection('users').findOne({ phoneNumber: phoneNumber });
      if (user_phone_check) {
        const otp = Math.floor(1000 + Math.random() * 9000);
        const ttl = 60 * 60 * 1000;
        const expires = new Date().getTime() + ttl;
        const otpData = `${phoneNumber}.${otp}.${expires}`;
        const OTP_KEY = "pnc1234"
        const hash = crypto.createHmac("sha256", OTP_KEY).update(otpData).digest("hex");
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
          message: custom_message.PHONE_NOT_FOUND
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

  verifyPhoneOtp: async (req, res, next) => {

    let {
      phoneNumber,
      phoneOtpKey,
      otp
    } = req.body;

    let [hashValue, expires] = phoneOtpKey.split(".");
    const OTP_KEY = "pnc1234"
    let now = new Date().getTime();
    if (now > parseInt(expires)) {
      const otp = Math.floor(1000 + Math.random() * 9000);
      const ttl = 60 * 60 * 1000;
      const expires = new Date().getTime() + ttl;
      const data1 = `${phoneNumber}.${otp}.${expires}`;
      const OTP_KEY = "pnc1234"
      const hash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
      const fullHash = `${hash}.${expires}`;
      return res.status(200).json({
        success: true,
        status_code: custom_error.CODE_200,
        status_msg: custom_error.MSG_200,
        showUser: 1,
        message: custom_message.OTP_SENT,
        response: {
          phoneOtpKey: fullHash,
          otp: otp
        }
      });
    }
    let data1 = `${phoneNumber}.${otp}.${expires}`;
    let newCalculatedHash = crypto.createHmac("sha256", OTP_KEY).update(data1).digest("hex");
    if (newCalculatedHash === hashValue) {
      let updateQuery = { phoneNumber: phoneNumber };
      var updateQueryData = { $set: { isPhoneVerified: 1 } };
      conn.collection('users').updateOne(updateQuery, updateQueryData, function (err, data) {
        if (err) {
          return res.status(500).json({
            success: false,
            status_code: custom_error.CODE_500,
            status_msg: custom_error.MSG_500,
            showUser: 1,
            message: custom_message.DB_CONN_ERROR
          });
        } else {
          return res.status(200).json({
            success: true,
            status_code: custom_error.CODE_200,
            status_msg: custom_error.MSG_200,
            showUser: 1,
            message: custom_message.VERIFICATION_SUCCESS
          });
        }
      })
    } else {
      return res.status(500).json({
        success: false,
        status_code: custom_error.CODE_500,
        status_msg: custom_error.MSG_500,
        showUser: 1,
        message: custom_message.VERIFICATION_FAILED
      });
    }
  },



}
