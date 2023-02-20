// Serve index.html on port 3000
require('dotenv').config({path:'info.env'});
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const {check, validationResult} = require('express-validator')
const sgMail = require('@sendgrid/mail');



// Parameters
const app = express();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Client, result } = require('pg');

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
sgMail.setApiKey(process.env.SENDGRID_API_KEY);



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


//Functions
function sendVerificationEmail(email, token, res){

    // Construct the verification link
    const verificationLink = `http://localhost:8080/verify?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    // Construct the email message


    const message = {
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Verify your email address',
        text: `Please click the following link to verify your email address: ${verificationLink}`,
        html: `Please click <a href="${verificationLink}">here</a> to verify your email address.`
    };

    // Send the verification email
/*
    const message = {
        to: email,
        from: 'abbyammo13@gmail.com',
        subject: 'Verify Your Email',
        html: `
        <p>Hi there,</p>
        <p>Please use the following verification code to verify your email address:</p>
        <h1>${token}</h1>
      `,
    };

 */

    // Send the email
    sgMail
        .send(message)
        .then((response) => {
            //console.log(response[0].statusCode)
            //console.log(response[0].headers)
            return res.render("sentemail", { email: email});
        })
        .catch((error) => {
            console.error(error)
        })
}

function verifyUser(client, email, token){



}




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

app.get('/email-sent',( req,res) => {
    res.render('sentemail', {email: '' })
})
app.post('/login', (req,res)=>{
})

app.post('/SignUp', [
    check('username').isLength({ min: 5 }).withMessage("Username must have a minimum of 5 characters"),
    check('username').isAlphanumeric().withMessage("Username must be an alphanumeric value"),
    check('password').isLength({ min: 8 }).withMessage("Password must have minimum of 8 length"),
    check('email').isEmail().withMessage("Please put a valid email address" )

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
        let email = req.body.email.replace(/[^\w@.-]/gi, "");

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

        // Generate a unique verification token for email verification
        const token = crypto.randomBytes(20).toString('hex');
        // Insert the new user into the "users" table
        const query = {
            text: 'INSERT INTO users (username, password, email, isverified, verificationtoken) VALUES ($1, $2, $3, $4, $5)',
            values: [username, hashedPassword, email, false, token]
        };
        client.connect()
            .then(() => client.query(query))
            .then(() => sendVerificationEmail(email, token, res))
            .catch(err => console.error(err))
            .finally(() => client.end());
    }

    //res.render('index')

})

// Route for handling email verification
app.get('/verify', async (req, res) => {
    console.log('this got triggered')
    // Extract the email and token from the URL query string
    const email = req.query.email;
    const token = req.query.token;
    console.log(email, token)

    // Query the database to find the user with the corresponding email and token
    const query = {
        text: 'SELECT * FROM users WHERE email = $1 AND verificationtoken = $2',
        values: [email, token]
    };
    const isVerified = true
    // Use a SQL parameterized query to update the 'is_admin' column for the user with the specified email
    const updateQuery = {
        text: 'UPDATE users SET isverified = $1 WHERE email = $2 AND verificationtoken = $3',
        values: [isVerified, email, token],
    };




    client.connect()
        .then(() => client.query(query))
        .then(()=> client.query(updateQuery))
        .then(()=> console.log(`Updated ${result.rowCount} row(s)`))
        .catch(err => console.error(err))
        .finally(() => {
            client.end();
        });


})



app.listen(port, () => console.log(`Example app listening on port ${port}!`));



