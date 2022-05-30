const JWT = require('jsonwebtoken')
const createError = require('http-errors')
const client = require('./init_redis')

module.exports = {

  signAccessToken: (userId) => {
    return new Promise((resolve, reject) => {
      const payload = {
        data: userId
      }
      const secret = "48f234b26ecdd84220f1a8a85d13496874041d6b1eab09c4506ae152c2bebd0a"
      const options = {
        expiresIn: '1h'
      }
      JWT.sign(payload, secret, options, (err, token) => {
        if (err) {
          console.log(err.message)
          reject(createError.InternalServerError())
          return
        }
        resolve(token)
      })
    })
  },

  verifyAccessToken: (req, res, next) => {
    if (!req.headers['authorization']) return next(createError.Unauthorized())
    const authHeader = req.headers['authorization']
    const bearerToken = authHeader.split(' ')
    // const token = bearerToken[1]
    const token = authHeader;
    JWT.verify(token, "48f234b26ecdd84220f1a8a85d13496874041d6b1eab09c4506ae152c2bebd0a", (err, payload) => {
      if (err) {
        const message =
          err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message
        return next(createError.Unauthorized(message))
      }
      req.payload = payload
      next()
    })
  },
  
  signRefreshToken: (userId) => {
    return new Promise((resolve, reject) => {
      const payload = {
        data: userId
      }
      const secret = "fabff2fa3833326be2e4170e1ad3e5c1d4639752197bc5175dfb75c51f737dbb"
      const options = {
        expiresIn: '1y'
      }
      JWT.sign(payload, secret, options, (err, token) => {
        if (err) {
          console.log(err.message)
          reject(createError.InternalServerError())
        }
        client.SET(userId, token, 'EX', 365 * 24 * 60 * 60, (err, reply) => {
          if (err) {
            console.log(err.message)
            reject(createError.InternalServerError())
            return
          }
          resolve(token)
        })
      })
    })
  },
  
  verifyRefreshToken: (refreshToken) => {
    return new Promise((resolve, reject) => {
      JWT.verify(
        refreshToken,
        "fabff2fa3833326be2e4170e1ad3e5c1d4639752197bc5175dfb75c51f737dbb",
        (err, payload) => {
          if (err) return reject(createError.Unauthorized())
          console.log(payload.data)
          const userId = payload.data
          client.GET(userId, (err, result) => {
            if (err) {
              console.log(err.message)
              reject(createError.InternalServerError())
              return
            }
            if (refreshToken === result) return resolve(userId)
            reject(createError.Unauthorized())
          })
        }
      )
    })
  },
}
