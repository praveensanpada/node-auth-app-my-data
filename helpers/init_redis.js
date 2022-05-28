const redis = require('redis')

const client = redis.createClient({
  port: 6379,
  host: 'http://ec2-34-221-70-16.us-west-2.compute.amazonaws.com',
  // password: "password"
})

client.on('connect', () => {
  console.log('Client connected to redis...')
})

client.on('ready', () => {
  console.log('Client connected to redis and ready to use...')
})

client.on('error', (err) => {
  console.log(err.message)
})

client.on('end', () => {
  console.log('Client disconnected from redis')
})

// process.on('SIGINT', () => {
//   client.quit()
// })

module.exports = client
