require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static('public')); //use the location for our css
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true}); //Skapar connection till MongoDB med namnet userDB -Se i Compass

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
}); //Skapar en ny userSchema i mongoDB och Sparar email & password i mongoDB 


userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); 
//Kommer att kryptera(encrypt) hela databasen
//Lägger till encryptedFields for att kategorisera ut och endast kryptera "password" -i detta fall.

const User = new mongoose.model('User', userSchema); //Skapar User för userSchema

/* 
### ALL ROUTES ###
*/ 
app.get('/', function(req, res){
    res.render('home') //Skickar användare till home som standard, utgår ifrån Home
});


//LOGIN ROUTE ----------------------
app.get('/login', function(req, res){
    res.render('login') //Skickar användaren till Login
});



//REGISTRATION ROUTES ----------------------
app.get('/register', function(req, res){
    res.render('register') //Skickar användaren till Register
});

app.post('/register', function(req, res){
    const newUser = new User({
        email: req.body.username, //Hämtar Username ifrån register-sidan
        password: req.body.password //Hämtar Password ifrån register-sidan
    }); 

    newUser.save(function(err){
        if (err) {
            console.log(err);
        } else {
            res.render('secrets') //Skickar användaren till sidan Secrets(Loggar in)
        }
    });
});

//LOGIN ROUTES ----------------------
app.post('/login', function(req, res){
    const username = req.body.username;
    const password = req.body.password; 


    //Letar i userDB efter inmatad liknelse, om den hittar en identisk sparad ObjectID så kommer den att matcha och logga in
    User.findOne({email: username}, function(err, foundUser){
        if (err) {
            // Error ifall Username och Password inte matchar som i userDB/Compass
            console.log(err);
        } else {
            if (foundUser) {
                //Ifall password matchar med username i userDB så kommer den att logga in, i annat fall blir det error
                if (foundUser.password === password) {
                    res.render('secrets'); 
                    //Ifall username och password är korrekt så skickas användaren vidare till Secrets-sidan, vilket innebär att användaren blivit autentiserade
                }
            }
        }
    });
});





app.listen(3000, function() {
    console.log("Server running on port 3000 BIATCH");
}); 