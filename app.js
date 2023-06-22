require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

//Setting up session
app.use(session({  
  secret: "Ourlittlesecret.",
  resave: false,
  saveUninitialized: false
}));

//initialize the passport
app.use(passport.initialize());
//Setting up session to use the passport
app.use(passport.session());

const connectDB = async() =>{
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
  password: String
});

//passport plugin for hash and salt user passwords before saving into mongoose DB
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", async(req, res) =>{
    try {
      res.render("home");  
    } catch (error) {
      console.log(error);  
    }
    
});

app.get("/login", async(req, res) =>{
    try {
        res.render("login");  
      } catch (error) {
        console.log(error);  
      } 
});

app.get("/register", async(req, res) =>{
    try {
        res.render("register");  
      } catch (error) {
        console.log(error);  
      } 
});

app.get("/secrets", async(req, res)=>{
    try {
      if(req.isAuthenticated()){
        res.render("secrets");
      } else {
        res.redirect("/login");
      }   
    } catch (error) {
        console.log(error);
    }
});

app.get("/logout", async (req, res) => {
    try {
         req.logout(function(err){
            if(err){
                console.log(err);
                process.exit(1);
            }
            res.redirect("/");
         }); 
                
    } catch (error) {
        console.log(error);        
    }    
});

app.post("/register", async(req, res) => {
  try {
    await User.register({username: req.body.username}, req.body.password).then(function(user){
      passport.authenticate("local")(req, res, function(){//this call back only triggers when successfull authentication is done
        res.redirect("/secrets");
      });
    });
  } catch (error) {
      console.log(error);
      res.render("/register");
  }     
});

app.post("/login", async(req, res) =>{
  try {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, async(err) => {
      if(err){
        console.log(err);
      } else {
        await passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  } catch (error) {
      console.log(error)
  }  
    
});

connectDB().then(function(){
    app.listen(PORT, function(){
      console.log(`Server started. Listening on port ${PORT}`);
    });
});