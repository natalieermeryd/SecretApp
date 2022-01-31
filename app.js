const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');

const app = express();

app.use(express.static('public')); //use the location for our css
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

/* 
### ALL ROUTES ###
*/ 
app.get('/', function(req, res){
    res.render('home')
});

app.get('/login', function(req, res){
    res.render('login')
});
app.get('/register', function(req, res){
    res.render('register')
});







app.listen(3000, function() {
    console.log("Server running on port 3000 BIATCH");
}); 