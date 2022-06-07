const express = require('express')
const morgan = require('morgan')
const createError = require('http-errors')
require('dotenv').config()
require('./helpers/init_mongodb')
const { verifyAccessToken } = require('./helpers/jwt_helper')
require('./helpers/init_redis')
var conn = require('./helpers/init_mongodb');
const AuthRoute = require('./Routes/Auth.route')
var ObjectId = require('mongodb').ObjectId;

const app = express()
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.get('/', verifyAccessToken, async (req, res, next) => {
  console.log(req.payload.data)

  let myUuid = new ObjectId(req.payload.data)
  let user_phone_check = await conn.collection('users').findOne({ _id: myUuid });
  console.log(user_phone_check)
  res.send('Hello from express. Id => ' + req.payload.data)
})

app.use('/api/v1/auth', AuthRoute)

app.use(async (req, res, next) => {
  next(createError.NotFound())
})

app.use((err, req, res, next) => {
  res.status(err.status || 500)
  res.send({
    error: {
      status: err.status || 500,
      message: err.message,
    },
  })
})

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
