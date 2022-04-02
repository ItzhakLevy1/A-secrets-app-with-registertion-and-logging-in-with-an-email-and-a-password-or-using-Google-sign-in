require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");   // This package will salt and hash all passwords for us.
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({   // Instructing our app to use the session package.
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());   // Instructing our app to initialize and use the passport package.
app.use(passport.session());   // Instructing our app to use the passport for dealing with the seassions.

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

// By adding "new mongoose.Schema this is now an object created from the "mongoose.Schema" class as required in the mongoose-encryption documentaion (and no longer a simple javascript object).
const userSchema = new mongoose.Schema ({   
  email: String,
  password: String,
  googleId: String, 
  secret: String
});

userSchema.plugin(passportLocalMongoose);   // This is how we would save our users into our data base.
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());  // Using passport-local-mongoose we will authenticate users using their username and passwords
                                            
passport.use(User.createStrategy());



passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user) {
    done(err, user);
  });
});




passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function(req, res){
  res.render("home");
});

// A route fot the "Sign In with Google" button.
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));   // Initializing authentication with the google servers "google" asking them for the user's profile "scope: ["profile"]" using the "GoogleStrategy".

  app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),   //Authenticating the user locally and saving their login session, Should the authentication fail the user will be redirected to the login page.
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){   // In every login session passport saves that users details into the "req" variable.
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){   // Here we are relaying on session and passport and passportLocal and passportLocalMongoose
  User.find({"secret": {$ne: null}}, function(err, foundUsers){// Using our "User" model we look into our database collection and find all of the places where the field secret actually has a value.
    if (err){
      console.log(err);
    } else {
      if (foundUsers) { // If a user was found.
        res.render("secrets", {usersWithSecrets: foundUsers});  // We will render the secrets page and pass the "usersWithSecrets" variable which represents users that have a Secret field in our data base and we will pass "foundUsers" as a value for this variable.
      }
    }
  });  
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){   // If a user is already logged-in we will redirect them to the submit page, authentication will be saved only as long as the page is not closed or refreshed.
    res.render("submit");
  } else {
    res.redirect("/login");   //  They will be refered to the log in page.
  }
});

app.post("/submit", function(req, res) {  // Deginning the courrent user inside the data base and saving the secret in to their file.
  const submittedSeceret = req.body.secret  // A seceret the user has subbmited, we can access "req.body.secret" through the "name="secret" in the submit.js file.

console.log(req.user.id);  // Here we can access the user name once a user is logged in and a secret has been submited.
  
User.findById(req.user.id, function(err, foundUser){
  if (err) {
    console.log(err);
  } else {
    if (foundUser) {
      foundUser.secret = submittedSeceret;
      foundUser.save(function(){
        res.redirect("/secret");  // Once a logged in user has submited a secret we redirect them to the secrets page.
      });
    }
  }
});
});

app.get("/logout", function(req, res){  // De-authenticating a user and ending a user's session to allow loging out using passport.
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){
 
  User.register({username: req.body.username}, req.body.password, function(err, user){  // 1. Tapping the "User" model and calling the method "register" on it which comes from the passport local mongoose package, the "username" gets the info that was submited by the user in the user name field (as a JavaScript object), 2. "req.body.password" is the password that the user has entered, 3. And finally a callback which eiher gives us an error or the new registered user.
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){  // If there are no errors we will authenticate our user using passport in a "local" type authentication which sets up a cookie that saves their current logged-in session and tell the browser to hold on to that cookie.
        res.redirect("/secrets");
      });
    }
  });

});


app.post("/login", function(req, res){
 const user = new User ({   // Creating a new user from our mongoose model.
  username: req.body.username,  // The "username" from the login form username field.
  password: req.body.password   // The "password" from the login form password field.
 })



// Using passport's "login()" function by calling it on the request object to login the users and authenticate them.
req.login(user, function(err){  // "user" is the new user that comes in from the log in credentials that the user provided on our log in page.
  if (err) {
    console.log(err);
  } else {
    passport.authenticate("local")(req, res, function(){  // If there are no errors we will authenticate our user using passport in a "local" type authentication which sets up a cookie that saves their current logged-in session.
      res.redirect("/secrets");
    });
  }
});
});

app.listen(3000, function(req, res){
  console.log("Server started on port 3000.");
});
