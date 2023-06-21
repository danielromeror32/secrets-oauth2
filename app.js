require('dotenv').config()
const express = require ("express");
const ejs = require ("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

app.use(session({
    secret: 'Ourlittlesecret.',
    resave: false,
    saveUninitialized: false
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB');


const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String,
    facebookId:String
  });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

passport.deserializeUser(function(id, done) {
    User.findById(id).exec()
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
});

// ----------- GOOGLE
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
// --------- FACEBOOK
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", 
passport.authenticate('google', { failureRedirect: "/login" }),
function(req, res) {
// Successful authentication, redirect to secrets page.
res.redirect('/secrets');
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

  app.get("/auth/facebook/secrets", 
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
  // Successful authentication, redirect to secrets page.
  res.redirect('/secrets');
  });
  



app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
   User.find({"secret":{$ne: null}}).then(foundUsers =>{
        if (foundUsers){
            res.render("secrets", {userWithSecrets: foundUsers})
        }
   });
});


app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
        
    }
});

app.post("/submit", function(req, res){
    const submitSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id).then(foundUser =>  {
        if(foundUser){
            foundUser.secret = submitSecret;
            foundUser.save().then(() =>{
                res.redirect("/secrets");
            })  .catch(error => {
                // Manejo de errores
                console.error("Error to save the user", error);
                // Responder al cliente con un mensaje de error o redirigir a una página de error
                res.status(500).send("Error to save the user");
              });
        }
    }).catch((error) => {
        console.error('Error to save user:', error);
    });
});

app.get("/logout", function(req, res){
        req.logout(function(err) {
          if (err) { 
            return next(err); 
        }
          res.redirect('/');
        });
})

app.post("/register", function(req, res){
    User.register({username: req.body.username},
    req.body.password, function(err, user){
    if (err) {
        console.log(err);
        res.redirect("/register");
    } else {
        passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
        });
    }
    })
});

app.post("/login", passport.authenticate("local"), function(req, res){
    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) { 
            return next(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
        
      });

});

app.listen(3000 , function(){
    console.log("Server started on port 3000");
});