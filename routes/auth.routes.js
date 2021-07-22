const router = require('express').Router();
const bcryptjs = require('bcryptjs');
const User = require('../models/User.model');
const mongoose = require('mongoose');
const { isLoggedIn, isLoggedOut } = require('./../middleware/route-guard');

// GET - display sign up form

router.get('/signup', isLoggedOut, (req, res) => {
  res.render('auth/signup');
});

// POST - process form data
router.post('/signup', isLoggedOut, (req, res, next) => {
  //extraccion de valores
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.render('auth/signup', {
      msg: 'All fields are mandatory'
    });
  }

  // make sure passwords are strong:
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render('auth/signup', { msg: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }

  //ENCRYPT
  bcryptjs
    .genSalt(10)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashPassword => {
      return User.create({
        username,
        email,
        passwordHash: hashPassword
      });
    })
    .then(usuarioCreado => {
      console.log('El usuario creado: ', usuarioCreado);
      req.session.usuarioActual = usuarioCreado;
      res.redirect('/userprofile');
    })
    .catch(error => {
      // copy the following if-else statement
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { msg: error.message });
      } else if (error.code === 11000) {
        res.status(500).render('auth/signup', {
          msg: 'El usuario o email ya existe. Intenta uno nuevo'
        });
      } else {
        next(error);
      }
    });
});

// GET profile page for current user

router.get('/userprofile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', {
    user: req.session.usuarioActual
  });
});

// GET

router.get('/login', isLoggedOut, (req, res) => {
  res.render('auth/login');
});

//proceso de autenticacion
router.post('/login', isLoggedOut, (req, res) => {
  console.log(req.session);

  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('auth/login', { msg: 'Por favor ingresa email y password' });
  }

  User.findOne({ email })
    .then(user => {
      // si el usuario nunca existio o no existe en base de datos
      if (!user) {
        // <== if there's no user with provided email, notify the user who is trying to login
        return res.render('auth/login', {
          msg: 'Email is not registered. Try with other email.'
        });
      }

      const autenticacionVerificada = bcryptjs.compareSync(password, user.passwordHash);

      // si el usuario se equivoco
      if (!autenticacionVerificada) {
        return res.render('auth/login', {
          msg: 'Wrong Password'
        });
      }

      // si el usuario coincide

      //crear en nuestro objeto SESSION una propiedad
      req.session.usuarioActual = user;
      console.log('Sesion Actualizada', req.session);
      return res.redirect('/userprofile');
    })
    .catch(e => console.log(e));
});

router.post('/logout', isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

module.exports = router;
