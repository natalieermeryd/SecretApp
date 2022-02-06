require('dotenv').config(); //Håller hemligheter hemliga
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//!!const encrypt = require('mongoose-encryption'); -Raderar dessa för att istället använda HASHING
//!!const md5 = require('md5'); UTRADERAD//HASHING Password - Impossible to reverse
//!!const bcrypt = require('bcrypt'); UTRADERAD BCRYPT
//!!const saltRounds = 10; UTRADERAD BCRYPT SALTING
const session = require('express-session'); //Cookies and Sessions
const passport = require('passport');       //Cookies and Sessions  
const passportLocalMongoose = require('passport-local-mongoose'); //Cookies and Sessions
const GoogleStrategy = require('passport-google-oauth20').Strategy;//Using the const as a strategy
const findOrCreate = require('mongoose-findorcreate');
const rateLimit = require('express-rate-limit');

const MongoClient = require('mongodb').MongoClient;

const auditLog = require('audit-log'); // DECLARE AUDITLOG

const app = express();
//----SSL-----------------------
const https = require('https');
const http = require('http');//testmiljö
const fs = require("fs");
//---------------------------------


//AUDIT LOGGING -----------------------
//audit loggar i mongoDB, loggar user aktivitet 
auditLog.addTransport("mongoose", {connectionString: "mongodb://localhost/auditdb"})
//---------------------------------------

const PORT = process.env.PORT || 3000
const uri = process.env.MONGODB;


//SSL -private key and certifiering & Asymmetric encryption----------
//Certificate , hemliga nycklar till SSL/TSL, som tillåter hemlig kommunikation mellan server och browser
const options = {
    key: fs.readFileSync('nattas-key.pem'),
    cert: fs.readFileSync('nattas-cert.pem')
}; //----------------------------------

//Övervakar app mot attacker /Monitoring
app.use('/healthcheck', require('./routes/healthcheck.routes')); 

app.use(express.static('public')); //use the location for our css
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

//session cookies
app.use(session({
    secret:"Our little secret.",
    resave: false,
    saveUninitialized: false,
    //cookie: { secure: true }
}));

app.use(passport.initialize()); //starting passport encryption - passport startar kryptering
app.use(passport.session());    //passport starting session cookies - passport startar session cookies

//connection to our Mongo DB where we have a document for our users.
//if user registers with Google we can only see the Google ID and submitted Secret
//if user registers via the form, we can see username, encrypted password and secret   
mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true}); //Skapar connection till MongoDB med namnet userDB -Se i Compass
//mongoose.set("useCreateIndex", true); //this is no longer needed in Mongoose 6

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String, //id som hittar user som loggar in genom google, och inte skapar ny id varje gång i DB
    secret: String
}); //Skapar en ny userSchema i mongoDB och Sparar email & password i mongoDB 

//krypterar när man (call save plugin) , saltar och hashar automatiskt åt oss
userSchema.plugin(passportLocalMongoose); // call plugin save = crypting

 //dekrypterar (när man call find plugin) , hittar avändare genom google id eller skapar om user inte finns
userSchema.plugin(findOrCreate);          // call plugin find = decrypting


//UTKOMMENTERAT FÖR ATT ISTÄLLET ANVÄNDA HASHING SOM ÄR SÄKRARE KRYPTERING
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); 
//Kommer att kryptera(encrypt) hela databasen
//Lägger till encryptedFields for att kategorisera ut och endast kryptera "password" -i detta fall.


const User = new mongoose.model('User', userSchema); //Skapar User för userSchema i mongoDB


// PASSPORT------------------------------------
//Autentisering
passport.use(User.createStrategy());

//serialize skapar  krypterad cookie med personens id, funkar för alla strategies
// skapar cookies with user ID
passport.serializeUser(function(user, done){
    done(null, user.id)
}); 
//deserialize tar sönder cookie så vi kan identifiera personen
// "opens" the cookie to identify user by ID
passport.deserializeUser(function (id, done) {
    User.findById(id, function(err, user){
        done(err, user);
    });
});

//passport google oauth, autentiserar user med new google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", //URL från Google Developers
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //Instead of retrieving the info from the users google+-account, instead we're retrieving from the user-info 
  },                //hämtar info från userinfo inte google+ account -futureproofed

    //Auktorisering , google skickar accesstoken så att vi kan använda data så länge det behövs
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile)

        //installera paket mongoose findOrCreate, skapar el hittar id och profil genom googleid
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


/* ----------------------------------------
### ALL ROUTES ###
*/ 

//Lägger till en register-spärr där man endast kan logga in 10ggr/15min
const createLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // Limit each IP to 10 requests per `window` (we have set a window to be =  15 minutes)
	message: "Too many accounts created from this IP, please try again after 15 minutes",
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
}) //Lägger till en request-spärr där man endast kan requesta sidan 10ggr/15min
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // Limit each IP to 10 requests per `window` (we have set a window to be =  15 minutes)
	message: "Too many requests sent from this IP, please try again after 15 minutes",
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})


//**HOME ROUTE 
app.get("/", limiter, function(req, res){
    res.render("home") //Skickar användare till home som standard, utgår ifrån Home
});

//**PASSPORT AND GOOGLE ROUTE-------------------
//opens up window for using google-sign in
//passport auth med google strategy, popup ruta för att user ska logga in
app.get("/auth/google", //getting info from google-server | Asking google server for the users profile
    passport.authenticate('google', { scope: ["profile"] })
); //Denna route skickar användaren vidare till google-inloggning

//google skickar tbx user, autentiserar user lokalt och blir hänvisad till appen för login
app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets-page.
    res.redirect("/secrets");
  });


//**LOGIN ROUTE ----------------------
app.get("/login", limiter, function(req, res){
    res.render("login") //Skickar användaren till Login
});

//**TERMS ROUTE ----------------------
app.get("/terms", function(req, res){
    res.render("/terms") //Skickar användaren till Terms
});


//REGISTRATION ROUTES ----------------------
app.get("/register", limiter, function(req, res){
    res.render("register") //Skickar användaren till Register
});

//**SECRETS ROUTES ----------------------------
app.get("/secrets", function (req, res){
    if (req.isAuthenticated()){
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

//----ANOTHER SECRET ROUTE-------------------------
//hittar alla secrets som blir inskickade
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
//---------------------------------------------------


//**SUBMIT SECRET ROUTE-------------------------------
//if a user wants to access the /submit-page they need to be logged in 
//- if not, they will be redirected to Log In
//skicka in en secret, om dom inte är inloggade skickas dom till login först
app.get("/submit", function (req,res) {
    if(req.isAuthenticated()){
        res.render("submit")
    }else {
        res.redirect("/login");
    }
});


//secret blir inskickad
//när user blir aut, sparas info i req.user
//om samma user loggar in igen så lagras deras secret på deras id
//console.log(req.user.id);
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
//loggar ut användare avslutar session/cookies
app.get("/logout", function(req, res, next) {
    // remove the req.user property and clear the login session
    req.logout();
  
    // // don't destroy session data when logout is used 
    // req.session = null;
  
    // redirect to homepage
    res.redirect('/');
  });

/*
The user gets redirected to the Secrets-section if registration or log in = success.
If not, they remain on the same page
*/

//**REGISTER ROUTE NEW USER */

//om login lyckas kommer user in till secrets , annars blir user kvar på register
//registrerar nya anändare med passport med local strategy
app.post("/register", function(req, res){
  
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

//------OLD REGISTER ROUTE FOR BCRYPT PASSWORD AND SALTING------
// app.post('/register', function(req, res){

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     //Store hash in your password DB

//     const newUser = new User({
//         email: req.body.username, //Hämtar Username ifrån register-sidan
//         password: hash
//         //UTRADERAD MD5 --password: md5(req.body.password) //Hämtar Password ifrån register-sidan -md5 = hashing
//         }); 
//         newUser.save(function(err){
//             if (err) {
//                 console.log(err);
//             } else {
//                 res.render('secrets') //Skickar användaren till sidan Secrets(Loggar in)
//             }
//          });
//     });
// });
//----------------------------------------------------------------

//LOGIN ROUTES ----------------------
//kollar så att username och password matchar med passport
app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    }); 

    //auditlog funkade bara i denna function eftersom det är en post
    auditLog.logEvent(user.username, 'maybe script name or function',
    "what just happened", 'the affected target name perhaps', 'target id', 'additional info, JSON, etc.');
    
    //This req comes from passport
    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        } else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

//-----OLD LOGIN ROUTE FOR BCRYPT & SALTING-----------
// app.post('/login', function(req, res){
//     const username = req.body.username;
//     const password = req.body.password

//     //UTRADERAT MD5 ----const password = md5(req.body.password); //Lägger md5 här också för att kunna matcha den hashade lösenordet.  
//     //Letar i userDB efter inmatad liknelse, om den hittar en identisk sparad ObjectID så kommer den att matcha och logga in
//     User.findOne({email: username}, function(err, foundUser){
//         if (err) {
//             // Error ifall Username och Password inte matchar som i userDB/Compass
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function(err, result) {
//                // res == true
//                if (result === true) {
//                    res.render('secrets');
//                    //Ifall username och password är korrekt så skickas användaren vidare till Secrets-sidan, vilket innebär att användaren blivit autentiserade
//                }
//                 });

//                 //Ifall password matchar med username i userDB så kommer den att logga in, i annat fall blir det error
//                 //UTRADERAT MD5 ---if (foundUser.password === password) {
//             }
//         }
//     });
// });
//-------------------------------------------------------


//Accesslogging/Touring Test, recaptcha ser till att du inte är en robot
//räknar även antal försök till login
function recaptcha_callback() {
    var loginBtn = document.querySelector('#login-btn');
    loginBtn.removeAttribute('disabled');
    loginBtn.style.cursor = 'pointer';
}


// app.listen(3000, function() {
//     console.log("Server running on port 3000 BIATCH");
// });


//SSL 
http.createServer(app).listen(PORT, function(){
    console.log('info', `STARTED LISTENING ON PORT ${PORT} BIATCH!`);
  });
  
  https.createServer(options, app).listen(443, function(){
    console.log('HTTPS listening on 443');
  });