// Serve index.html on port 3000
require('dotenv').config({path:'info.env'});
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const {check, validationResult} = require('express-validator')
// Parameters
const app = express();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Client } = require('pg');

const client = new Client({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: process.env.database,
    password:  process.env.password,

    //Temporary for development environment, however for production version it should be true
    // ssl: true,
    ssl:{
        rejectUnauthorized: false,
    }

});




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
    check('username').isLength({ min: 5 }).withMessage("Username must have a minimum of 5 characters"),
    check('username').isAlphanumeric().withMessage("Username must be an alphanumeric value"),
    check('password').isLength({ min: 8 }).withMessage("Password must have minimum of 8 length"),
    //check('password').matches(/\d/).withMessage('Password must contain a number')

],(req,res)=>{
    //Validating the input upon sign-up to stop SQL Injection
    const errors = validationResult(req);
    //let error_string = "Error: Username or password is incorrect"
    if (!errors.isEmpty()) {
        return res.render("signUp", { errors: errors.array()});
    }else{
        /*
            Sanitize the inputs to prevent SQL injection
           The regular expression /[^\w\s]/gi matches any character that is not a word character (alphanumeric) or whitespace,
            and the replace() method replaces these characters with an empty string.
        */
        let username = req.body.username.replace(/[^\w\s]/gi, "");
        let password = req.body.password.replace(/[^\w\s]/gi, "");


        // Generate a salt using bcrypt
        const saltRounds = 10;
        const salt = bcrypt.genSaltSync(saltRounds);

        // Generate a pepper using crypto
        const pepper = crypto.randomBytes(16).toString('hex');

        // Function to hash a password with salt and pepper
            const saltedPassword = password + salt;
            const pepperedPassword = saltedPassword + pepper;
            const hashedPassword = bcrypt.hashSync(pepperedPassword, saltRounds);
            console.log(hashedPassword)



        // Insert the new user into the "users" table
        const query = {
            text: 'INSERT INTO users (username, password) VALUES ($1, $2)',
            values: [username, hashedPassword]
        };
        client.connect()
            .then(() => client.query(query))
            .then(() => console.log('User inserted'))
            .catch(err => console.error(err))
            .finally(() => client.end());





        res.redirect('/');
    }

    //res.render('index')

})



app.listen(port, () => console.log(`Example app listening on port ${port}!`));



