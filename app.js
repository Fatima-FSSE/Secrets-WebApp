require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

const connectDB = async() =>{
    try {
      const conn = await mongoose.connect(process.env.MONGO_URI);
      console.log(`MongoDb Connected: ${conn.connection.host}`);   
    } catch (error) {
        console.log(error);
    }
};

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = new mongoose.model("User", userSchema);

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

app.post("/register", function(req, res){
  bcrypt.hash(req.body.password, saltRounds, async function(err, hash) {
    try {
      const newUser = new User({
        email: req.body.username,
        password: hash
      });

      await newUser.save().then(function(){
      res.render("secrets");
      console.log("User Data has been saved successfully");
      });    
    } catch (error) {
       console.log(error); 
    }      
   });    
});

app.post("/login", async(req, res) =>{
    try {
        const username = req.body.username;
        const password = req.body.password;
        await User.findOne({email: username}).then(function(foundUser){
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result === true){
                      res.render("secrets");
                      console.log("Login Successfull");  
                    }
                    if(err){
                      console.log(err);
                    }
                });                
            }
        });
    } catch (error) {
        console.log("Unable to find User" + error);
    }
});


connectDB().then(function(){
    app.listen(PORT, function(){
      console.log(`Server started. Listening on port ${PORT}`);
    });
});