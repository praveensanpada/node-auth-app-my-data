const mongoose = require('mongoose')

let mongoose_url = "mongodb+srv://praveen:sanpada@test-database.ib5ey.mongodb.net/?retryWrites=true&w=majority"
mongoose
  .connect(mongoose_url, {
    dbName: "Test-Database",
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true,
  })
  .then(() => {
    console.log('mongodb connected.')
  })
  .catch((err) => console.log(err.message))

mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to db')
})

mongoose.connection.on('error', (err) => {
  console.log(err.message)
})

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose connection is disconnected.')
})

var conn = mongoose.connection;
module.exports = conn;
