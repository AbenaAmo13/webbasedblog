// Serve index.html on port 3000
require('dotenv').config({path:'info.env'});
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const {check, validationResult} = require('express-validator')
const nodemailer = require("nodemailer");


// Parameters
const app = express();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Pool, result } = require('pg');

const pool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: process.env.database,
    password:  process.env.password,
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


// async..await is not allowed in global scope, must use a wrapper
async function sendVerificationEmail(email, token,res) {

    // Construct the verification link
    const verificationLink = `http://localhost:8080/verify?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;

    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        host: process.env.email_host,
        port: process.env.email_port,
        secure: process.env.email_secure, // true for 465, false for other ports
        auth: {
            user: process.env.email_user, // generated ethereal user
            pass: process.env.email_pass, // generated ethereal password
        },
    });

    // send mail with defined transport object
    let info = await transporter.sendMail({
        from: process.env.email_user, // sender address
        to: email, // list of receivers
        subject: "Verification Link", // Subject line
        text: `Please click the following link to verify your email address: ${verificationLink}`, // plain text body
        html: `Please click <a href="${verificationLink}">here</a> to verify your email address.`
    });

    console.log("Message sent: %s", info.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>

    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.render("sentemail", { email: email});
}

function verifyUser(client, email, token) {


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

],(req,res)=> {
    //Validating the input upon sign-up to stop SQL Injection
    const errors = validationResult(req);
    //let error_string = "Error: Username or password is incorrect"
    if (!errors.isEmpty()) {
        return res.render("signUp", {errors: errors.array()});
    } else {
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

        pool.query(query)
            .then(() => sendVerificationEmail(email, token,res))
            .catch(err=>console.error(err))
    }
})

// Route for handling email verification
app.get('/verify', async (req, res) => {
    console.log('this got triggered')
    // Extract the email and token from the URL query string
    const email = req.query.email;
    const token = req.query.token;
    console.log(email, token)

    const isVerified = true
    const newToken = ''
    // Use a SQL parameterized query to update the 'is_admin' column for the user with the specified email
    const updateQuery = {
        text: 'UPDATE users SET isverified = $1, verificationtoken=$2 WHERE email = $3 AND verificationtoken = $4',
        values: [isVerified,'',email, token],
    };
    pool.query(updateQuery)
        .then(console.log('It works'))
        .catch(err=>console.log(err))

})



app.listen(port, () => console.log(`Example app listening on port ${port}!`));



