require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require("mongoose-findorcreate");
const { resolve } = require("path/win32");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(__dirname + '/public')); 
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: true }));

//Setting up session
app.use(
  session({
    secret: "Ourlittlesecret.",
    resave: false,
    saveUninitialized: false,
  })
);

//initialize the passport
app.use(passport.initialize());
//Setting up session to use the passport
app.use(passport.session());

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDb Connected: ${conn.connection.host}`);
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
};

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

//passport plugin for hash and salt user passwords before saving into mongoose DB
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//serialize workds with ANY Kind of authentication
//Passport packs user data(session id..) into cookie
passport.serializeUser(function (user, done) {
  done(null, user);
});

//passport open cookie, see user session id, authenticate them on our server
passport.deserializeUser(function (user, done) {
  done(null, user);
});

//Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://c3drnl-3000.csb.app/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ 
        email: profile.displayName,
        googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL:"https://c3drnl-3000.csb.app/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ 
        email: profile.displayName,
        facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", async (req, res) => {
  try {
    res.render("home");
  } catch (error) {
    console.log(error);
  }
});

//Google routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect  to secrets.
    res.redirect("/secrets");
  }
);

//Facebook routes
app.get("/login/federated/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", async (req, res) => {
  try {
    res.render("login");
  } catch (error) {
    console.log(error);
  }
});

app.get("/register", async (req, res) => {
  try {
    res.render("register");
  } catch (error) {
    console.log(error);
  }
});

app.get("/secrets", async (req, res) => {
  try {
    await User.find({ secret: { $ne: null } }).then(function (foundUsers) {
      res.render("secrets", { usersWithSecrets: foundUsers });
    });
  } catch (error) {
    console.log(error);
  }
});

app.get("/submit", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/submit", async (req, res) => {
  try {
    const submittedSecret = req.body.secret;
    await User.findById(req.user._id).then(function (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save().then(function () {
        res.redirect("/secrets");
      });
    });
  } catch (error) {
    console.log(error);
  }
});

app.get("/logout", async (req, res) => {
  try {
    req.logout(function (err) {
      if (err) {
        console.log(err);
        process.exit(1);
      }
      res.redirect("/");
    });
  } catch (error) {
    console.log(error);
  }
});

app.post("/register", async (req, res) => {
  try {
    await User.register(
      { username: req.body.username },
      req.body.password
    ).then(function (user) {
      //authenticating user with passport using local strategy
      passport.authenticate("local")(req, res, function () {
        //this call back only triggers when successfull authentication is done
        res.redirect("/secrets");
      });
    });
  } catch (error) {
    console.log(error);
    res.render("/register");
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    req.login(user, async (err) => {
      if (err) {
        console.log(err);
      } else {
        await passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });
  } catch (error) {
    console.log(error);
  }
});

connectDB().then(function () {
  app.listen(PORT, function () {
    console.log(`Server started. Listening on port ${PORT}`);
  });
});