const express = require('express');
const bcrypt = require('bcryptjs');
const knex = require('knex');
const session = require('express-session');
const knexSessionStore = require('connect-session-knex')(session);
const db_config = require('./knexfile');
const db = knex(db_config.development);
const restrictedRoutes = require('./restrictedRoutes');
const server = express();

const PORT = 9999;

server.use(express.json());
server.use(session({
  name: 'notsession',
  secret: ':^)',
  cookie: {
    maxAge: 1 * 24 * 60 * 60 * 1000
  },
  httpOnly: true,
  resave: false,
  saveUninitialized: false
}));

server.use('/api/restricted', restrictedRoutes);

server.post('/api/register', (req, res) => {
  const creds = req.body
  const hash = bcrypt.hashSync(creds.password, 14)
  creds.password = hash
  db('users')
    .insert(creds)
    .then(ids => {
      res.status(201).json(ids)
    })
    .catch(() => {
      res.status(500).json({
        error: 'Unable to register'
      })
    })
})

server.get('/api/login', (req, res) => {res.status(200).json({ message: "try sending a post request"})})

server.post('/api/login', (req, res) => {
  const creds = req.body
  db('users')
    .where({
      username: creds.username
    })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.userId = user.id
        res.status(200).json({
          message: `${user.username} is logged in`
        })
      } else {
        res.status(401).json({
          message: 'Check username and password'
        })
      }
    })
    .catch(() =>
      res.status(500).json({
        message: 'Please try logging in again.'
      })
    )
})

function protected(req, res, next) {
  if (req.session && req.session.userId) {
    next()
  } else {
    res.status(401).json({
      message: 'You shall not pass, not authenticated.'
    })
  }
}


server.get('/api/restricted/users', protected, (req, res) => {
  db('users')
    .select('id', 'username', 'password')
    .then(users => {
      res.json(users)
    })
    .catch(() => {
      res.status(500).json({
        message: 'Must be logged in'
      })
    })
})

server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        res.status(500).json({
          message: 'Failed'
        })
      } else {
        res.status(200).json({
          message: 'Logout successful'
        })
      }
    })
  } else {
    res.json({
      message: 'You are logged out'
    })
  }
})

server.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`)
})