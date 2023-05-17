const bcryptjs = require('bcryptjs')
const User = require('../models/User.model')
const jwt = require('jsonwebtoken')
const { isAuthenticated } = require('../middleware/jwt.middleware')

const router = require('express').Router()

router.get('/', (req, res, next) => {
  res.json('Auth good in here')
})

// POST to signup
router.post('/signup', async (req, res) => {
  // Generate the salt
  const salt = bcryptjs.genSaltSync(13)
  // Hash the password
  const passwordHash = bcryptjs.hashSync(req.body.password, salt)
  try {
    await User.create({ email: req.body.email, password: passwordHash })
    res.status(201).json({ message: 'New user created' })
  } catch (error) {
    console.log(error)
  }
})

// POST to login
router.post('/login', async (req, res) => {
  // Does user exists
  const potentialUser = await User.findOne({ email: req.body.email })
  if (potentialUser) {
    // Is the password correct
    if (bcryptjs.compareSync(req.body.password, potentialUser.password)) {
      // Password IS correct
      const authToken = jwt.sign({ userId: potentialUser._id }, process.env.TOKEN_SECRET, {
        algorithm: 'HS256',
        expiresIn: '6h',
      })
      res.json(authToken)
    } else {
      // Password ISN'T correct
    }
  } else {
    // No user found
  }
})

// GET to verify
router.get('/verify', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.pizza.userId)
  res.status(200).json({ message: 'User is authenticated', user })
})

module.exports = router
