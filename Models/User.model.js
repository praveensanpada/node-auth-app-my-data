const mongoose = require('mongoose')

var userSchema = new mongoose.Schema({
  email: { type : String , lowercase: true, unique : true, required : true },
  phoneNumber: { type : String },
  password: { type: String, required: true, },
  isGoogleAccount: { type: Number },
  firstName: { type: Number },
  lastName: { type: Number },
  countryCode: { type: String },
  birthDate: { type: Date },
  isPhoneVerified: { type: Number },
  isEmailVerified: { type: Number },
  isUserBlocked: { type: Number },
  userBlockReason: { type: String },
  isKycDone: { type: Number },
  bankProof: { type: Number },
  governmentId: { type: Number },
});



const User = mongoose.model('users', userSchema)
console.log("Users Collection Created !!")
module.exports = User
