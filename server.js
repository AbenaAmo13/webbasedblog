// Serve index.html on port 3000
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const {check, validationResult} = require('express-validator')
// Parameters
const app = express();


// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.set('views', 'views');




const port = 8080;



//Server statically
app.set('view engine', 'ejs');
app.use(express.static('client'));

// Body parser middleware
app.use(bodyParser.json());
//Force input to be encoded correctly.
app.use(bodyParser.urlencoded({ extended: true }));


//Routes
app.get('/', (req, res) => {
    res.render('index')
});

app.get('/login', (req, res) => {
   res.render('login')
});

app.get('/sign-up', (req, res) => {
   res.render('signUp', {errors: false})
});

app.post('/login', (req,res)=>{
})

app.post('/SignUp', [
    check('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
    check('username').isAlphanumeric().withMessage('Username must be alphanumeric'),
    check('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
    //check('password').matches(/\d/).withMessage('Password must contain a number')

],(req,res)=>{
    //Validating the input upon sign-up to stop SQL Injection
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render("signUp", { errors: errors.array() });
    }else{
        /*
            Sanitize the inputs to prevent SQL injection
           The regular expression /[^\w\s]/gi matches any character that is not a word character (alphanumeric) or whitespace,
            and the replace() method replaces these characters with an empty string.
        */
        let username = req.body.username.replace(/[^\w\s]/gi, "");
        let password = req.body.password.replace(/[^\w\s]/gi, "");
        res.redirect('/');
    }

    //res.render('index')

})



app.listen(port, () => console.log(`Example app listening on port ${port}!`));



