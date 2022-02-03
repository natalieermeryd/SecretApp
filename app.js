require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//!!const encrypt = require('mongoose-encryption'); -Raderar dessa för att istället använda HASHING
//!!const md5 = require('md5'); UTRADERAD//HASHING Password - Impossible to reverse
const bcrypt = require('bcrypt');
const saltRounds = 10;
// const session = require('express-session');
// const passport = require('passport');
// const passportLocalMongoose = require('passport-local-mongoose');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const findOrCreate = require('mongoose-findorcreate');

const MongoClient = require('mongodb').MongoClient;

const auditLog = require('audit-log');
const app = express();
// const https = require('https');
// const http = require('http');
// const fs = require("fs");

auditLog.addTransport("mongoose", {connectionString: "mongodb://localhost/auditdb"})

const PORT = process.env.PORT || 3000
const uri = process.env.MONGODB;


// const options = {
//     key: fs.readFileSync('nattas-key.pem'),
//     cert: fs.readFileSync('nattas-cert.pem')
// }; 


app.use('/healthcheck', require('./routes/healthcheck.routes'));

app.use(express.static('public')); //use the location for our css
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// //session cookies
// app.use(session({
//     secret:"Our little secret.",
//     resave: false,
//     saveUninitialized: true,
//     cookie: { secure: true }
// }));

// app.use(passport.initialize()); //starting passport encryption
// app.use(passport.session());    //passport starting session cookies

//connection to our Mono DB where we have a document for our users.
//if user registers with Google we can only see the Google ID and submitted Secret
//if user registers via the form, we can see username, encrypted password and secret   
mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true}); //Skapar connection till MongoDB med namnet userDB -Se i Compass
//mongoose.set("useCreateIndex", true); this is no longer needed in Mongoose 6

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
    //googleId: String,
    //secret: String
}); //Skapar en ny userSchema i mongoDB och Sparar email & password i mongoDB 

// userSchema.plugin(passportLocalMongoose); // call plugin save = crypting
// userSchema.plugin(findOrCreate);          // call plugin find = decrypting

//UTKOMMENTERAT FÖR ATT ISTÄLLET ANVÄNDA HASHING SOM ÄR SÄKRARE KRYPTERING
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); 
//Kommer att kryptera(encrypt) hela databasen
//Lägger till encryptedFields for att kategorisera ut och endast kryptera "password" -i detta fall.


const User = new mongoose.model('User', userSchema); //Skapar User för userSchema

//PASSPORT------------------------------------

// passport.use(User.createStrategy());

// // skapar cookies with user ID
// passport.serializeUser(function(user, done){
//     done(null, user.id)
// });
// // "opens" the cookie to identify user by ID
// passport.deserializeUser(function (id, done) {
//     User.findById(id, function(err, user){
//         done(err, user);
//     });
// });

// passport.use(new GoogleStrategy({
//     clientID: process.env.CLIENT_ID,
//     clientSecret: process.env.CLIENT_SECRET,
//     callbackURL: "http://localhost:3000/auth/google/secrets",
//     userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
//   },

//   function(accessToken, refreshToken, profile, cb) {
//       console.log(profile)

//     User.findOrCreate({ googleId: profile.id }, function (err, user) {
//       return cb(err, user);
//     });
//   }
// ));


/* ----------------------------------------
### ALL ROUTES ###
*/ 
//**HOME ROUTE 
app.get('/', function(req, res){
    res.render('home') //Skickar användare till home som standard, utgår ifrån Home
});

//**PASSPORT AND GOOGLE ROUTE-------------------
//opens upp window for using google-sign in
// app.get('/auth/google',
//     passport.authenticate('google', { scope: ['profile'] })
// );

// app.get('/auth/google/secrets', 
//   passport.authenticate('google', { failureRedirect: '/login' }),
//   function(req, res) {
//     // Successful authentication, redirect to secrets-page.
//     res.redirect('/secrets');
//   });


//**LOGIN ROUTE ----------------------
app.get('/login', function(req, res){
    res.render('login') //Skickar användaren till Login
});



//REGISTRATION ROUTES ----------------------
app.get('/register', function(req, res){
    res.render('register') //Skickar användaren till Register
});

//**SECRETS ROUTES ----------------------------
// app.get('/secrets', function (req, res){
//     //renders all submitted secrets 
//     User.find({'secret': {$ne: null}}, function(err, foundUsers){
//         if(err){
//             console.log(err)
//         } else {
//             if(foundUsers) {
//                 res.render('secrets', {usersWithSecrets: foundUsers});
//             }
//         }
//     });
// });

//-------------------------------------------
//if a user wants to access the /submit-page they need to be logged in 
//- if not, they will be redirected to Log In
// app.get('/submit', function (req,res) {
//     if(req.isAuthenticated()){
//         res.render('submit')
//     }else {
//         res.redirect('/login');
//     }
// });

//**SUBMIT SECRET ROUTE-------------------------------

// app.post('/submit', function(req, res) {
//     const submittedSecret = req.body.secret;

    //  Once the user is authenticated and their session gets saved, 
    //  their user details are saved to req.user.
    //  console.log(req.user.id);

//     User.findById(req.user.id, function(err, foundUser){
//         if (err) {
//             console.log(err)
//         } else {
//             if(foundUser) {
//                 foundUser.secret = submittedSecret;
//                 foundUser.save(function(){
//                     res.redirect('/secrets');
//                 });
//             }
//         }
//     });
// });

//-----------------------------------------------------

//**LOGOUT ROUTE------------------------------------------
// app.get('/logout', function(req, res, next) {
//     // remove the req.user property and clear the login session
//     req.logout();
  
//     // destroy session data
//     req.session = null;
  
//     // redirect to homepage
//     res.redirect('/');
//   });

/*
The user gets redirected to the Secrets-section if registration or log in = success.
If not, they remain on the same page
*/

//**REGISTER ROUTE NEW USER */

app.post('/register', function(req, res){

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //Store hash in your password DB

    const newUser = new User({
        email: req.body.username, //Hämtar Username ifrån register-sidan
        password: hash
        //UTRADERAD MD5 --password: md5(req.body.password) //Hämtar Password ifrån register-sidan -md5 = hashing
        }); 
        newUser.save(function(err){
            if (err) {
                console.log(err);
            } else {
                res.render('secrets') //Skickar användaren till sidan Secrets(Loggar in)
            }
         });
    });
});

//LOGIN ROUTES ----------------------
app.post('/login', function(req, res){
    const username = req.body.username;
    const password = req.body.password

    //UTRADERAT MD5 ----const password = md5(req.body.password); //Lägger md5 här också för att kunna matcha den hashade lösenordet.  
    //Letar i userDB efter inmatad liknelse, om den hittar en identisk sparad ObjectID så kommer den att matcha och logga in
    User.findOne({email: username}, function(err, foundUser){
        if (err) {
            // Error ifall Username och Password inte matchar som i userDB/Compass
            console.log(err);
        } else {
            if (foundUser) {
                bcrypt.compare(password, foundUser.password, function(err, result) {
               // res == true
               if (result === true) {
                   res.render('secrets');
                   //Ifall username och password är korrekt så skickas användaren vidare till Secrets-sidan, vilket innebär att användaren blivit autentiserade
               }
                });

                //Ifall password matchar med username i userDB så kommer den att logga in, i annat fall blir det error
                //UTRADERAT MD5 ---if (foundUser.password === password) {
            }
        }
    });
});





app.listen(3000, function() {
    console.log("Server running on port 3000 BIATCH");
});

// http.createServer(app).listen(PORT, function(){
//     console.log('info', `STARTED LISTENING ON PORT ${PORT} BIATCH!`);
//   });
  
//   https.createServer(options, app).listen(443, function(){
//     console.log('HTTPS listening on 443');
//   });