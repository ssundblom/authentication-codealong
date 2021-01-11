import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt'

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(123).toString('hex')
  }
})

const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header('Authorization') })
  if (user) {
    req.user = user
    next()
  } else {
    res.status(401).json({ loggedOut: true })
  }
}
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello schemllo')
})

app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body
    const SALT = bcrypt.genSaltSync(10);
    const user = new User({ name, email, password: bcrypt.hashSync(password, SALT) })
    user.save()
    res.status(201).json({ id: user._id, accessToken: user.accessToken })
  } catch (err) {
    console.log(err)
    res.status(400).json({ message: 'Could not create juser', errors: err.errors })
  }
})

app.get('/secrets', authenticateUser)
app.get('/secrets', (req, res) => {
  res.json({ secret: 'This is super secret schhhhh' })
})

app.post('/sessions', async (req, res) => {
  const user = await User.findOne({email: req.body.email})
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({userId: user._id, accessToken: user.accessToken})
  } else {
    res.json({notFound: true})
  }

})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
