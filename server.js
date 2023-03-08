// Serve index.html on port 3000
require('dotenv').config({path:'info.env'});
const express = require('express');
const https = require('https');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const {check, validationResult} = require('express-validator')
const nodemailer = require("nodemailer");
const session = require('express-session');
const { v4: uuid } = require('uuid')



// Parameters
const app = express();
const crypto = require('crypto');
const algorithm = 'aes-256-cbc'; // encryption algorithm
const key = process.env.my_secret_key; // secret key used for encryption
const iv = crypto.randomBytes(16); // initialization vector
const oneDay = 1000 * 60 * 60 * 24;


const { Pool, result } = require('pg');

const pool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: process.env.database,
    password:  process.env.password,
});


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


app.use(session({
    secret: process.env.secret_key,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: oneDay} //Secure should be set to true--> working on this

}));

// async..await is not allowed in global scope, must use a wrapper
async function sendVerificationEmail(email, token,res) {

    // Construct the verification link
    const verificationLink = `http://localhost:8080/verify?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Verify your email address',
        text: `Please click the following link to verify your email address: ${verificationLink}`,
        html: `Please click <a href="${verificationLink}">here</a> to verify your email address.`
    });
    console.log("Message sent: %s", message.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.render("sentemail", { email: email});
}


async function TwoFactorEmail(email, token,res) {
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'One Time PassCode',
        text: `This is your one time token: ${token}`,
        html: `This is your token: <b> ${token}</b>`
    });
    console.log("Message sent: %s", message.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.render("verifyToken", { message: email, errors: false, email: email});
}


function encrypt(word) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(word, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
}

function storePasswordInfo(filename, passwordData){
    let obj = {
        user_info: []
    };
    fs.readFile(filename, 'utf8', function readFileCallback(err, data){
        if (err){
            console.log(err);
        } else {
            obj = JSON.parse(data); //now it an object

            obj.user_info.push(passwordData); //add some data
            let user_json = JSON.stringify(obj); //convert it back to json
            fs.writeFile(filename, user_json, 'utf8', function (err) {
                if (err) throw err;
                console.log('Saved!');
            }); // write it back
        }});
}


async function getPasswordInfo(email) {
    try {
        const saltData = await fs.promises.readFile('info/salts.json', 'utf8');
        const saltObj = JSON.parse(saltData);
        const userSalt = saltObj.user_info.find(u => u.email === email);
        const pepperData = await fs.promises.readFile('info/pepper.json', 'utf8');
        const pepperObj = JSON.parse(pepperData);
        const userPepper= pepperObj.user_info.find(u => u.email === email);
        if(userPepper && userSalt){
            return {salt: userSalt.salt, pepper: userPepper.pepper};
        }else{
            return null;
        }
        //return userSalt ? userSalt.salt : null;
    } catch (error) {
        console.log(error);
        return null;
    }
}


function generateOTP() {
    const secret = crypto.randomBytes(16).toString('hex');
    const time = Math.floor(Date.now() / 300000); // current time in 30 second intervals
    const hash = crypto.createHmac('sha1', secret).update(time.toString()).digest('hex');
    const offset = parseInt(hash.substr(-1), 16); // convert last character of hash to decimal
    const otp = (parseInt(hash.substr(offset * 2, 8), 16) & 0x7fffffff).toString().substr(-6); // generate 6-digit OTP
    return otp;
}


//Routes
app.get('/', (req, res) => {
    res.render('index')
});

app.get('/login', (req, res) => {
   res.render('login', {logout: 'false', message: false, errors: false})
});

app.get('/sign-up', (req, res) => {
   res.render('signUp', {errors: false})
});

app.get('/email-sent',( req,res) => {
    res.render('sentemail', {email: email})
})

app.get('/blogDashboard', (req, res)=>{
    if(!req.session.usermail){
        //Will be changed to contain name rather than email
        res.send('Unauthorised Request')
    }else{
        res.render('blogDashboard', {firstname: req.session.usermail})
    }
})

app.get('/twofa', (req, res)=>{
  res.render('verifyToken', {errors:false, message:false, email:false})
})

app.post('/twofa', [
    check('verificationtoken').isNumeric().exists({checkFalsy: true}).isLength({max:6}),
    check('email').exists({checkFalsy: true}).isEmail(),
    ],
    (req, res)=>{
        const errors = validationResult(req);
        console.log('it appears here')
        if(!errors.isEmpty()){
            return res.render("verifyToken", {errors: "Invalid token", email:false, message: false});
        }else{
            let currentTime = Date.now();
            const timeDifference = 24 * 60 * 60 * 1000; //24 hrs testing
            //sanitized input to prevent XSS attacks
            const sanitizedTokenInput = req.body.verificationtoken.replace(/[<>&'"]/g, '');
            let emailInput = req.body.email.replace(/[^\w.@+-]/g, '');
            console.log(emailInput)
            console.log(sanitizedTokenInput)


            //Check if the token in the link is correct as the one in the database
            const twofatokenquery = {
                text: 'SELECT otp FROM otps WHERE otp = $1 AND $2 - creationtime < $3 AND used = $4 AND email = $5 ',
                values: [sanitizedTokenInput, currentTime,timeDifference, false, emailInput],  // 24 hours in milliseconds
            };

            const deleteTokenQuery = {
                text: 'DELETE FROM otps WHERE otp = $1  AND email= $2',
                values: [sanitizedTokenInput, emailInput] // 24 hours in milliseconds
            };

            pool.query(twofatokenquery).then((result)=>{
                console.log(result.rows[0]);
                if(result.rows.length > 0){
                    //Validate the user
                    req.session.usermail = emailInput;
                    res.redirect('/blogDashboard');
                    pool.query(deleteTokenQuery)
                }else{
                   res.render('verifyToken', {errors:'Invalid token', email:emailInput, message: emailInput})
                }
            })

        }


})




app.post('/logout', (req, res)=> {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.status(500).send('Server Error');
        } else {
            res.redirect('/');
        }
    });

    res.clearCookie('connect.sid');
})
app.post('/login', [
    check('email').exists({checkFalsy: true}).isEmail(),
    check('password').isLength({ min: 8 }),


],async(req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render("login", {errors: "Username and/or password is incorrect", message:false});
    }else{
        //Username and password:
        const email = req.body.email;
        let password = req.body.password.replace(/[^\w\s]/gi, "");
        //Converting password to hash version to verify the password
        const password_info = await getPasswordInfo(email);
        const password_salt = password_info.salt;
        const password_pepper = password_info.pepper;
        const saltedPassword = password + password_salt
        const pepperedPassword = saltedPassword + password_pepper;
        const hashedPassword = crypto.createHash('sha256').update(pepperedPassword).digest('hex');

        const userQuery = {
            text: 'SELECT email, password FROM users WHERE email = $1 AND password =$2 AND isverified =$3',
            values: [email, hashedPassword, true] // 24 hours in milliseconds
        };

        pool.query(userQuery).then((result)=>{
            if(result.rows.length> 0 ){
                //Update the token with the new token:
                let token = generateOTP();
                let creationTime = Date.now();
                const selectQuery = {
                    text: 'SELECT otp, used FROM otps WHERE email = $1',
                    values: [email] // 24 hours in milliseconds
                };
                pool.query(selectQuery)
                    .then((result)=>{
                        if(result.rows.length > 0){
                            const updateQuery = {
                            text: 'UPDATE otps SET used = $1, otp = $2, creationtime= $3 WHERE email = $4',
                            values: [false, token, creationTime, email]
                        };
                            pool.query(updateQuery);
                        }else{
                            //This means that there has been no otp set before
                            const query = {
                                text: 'INSERT INTO otps (email, otp, used, creationtime) VALUES ($1, $2, $3, $4)',
                                values: [email, token, false, creationTime]
                            };
                            pool.query(query)
                        }

                    })
                //Two factor Authentication.
                //sendVerificationEmail(email, token, res);
                TwoFactorEmail(email, token, res)
               // res.render('verifyToken', {errors: false, message:email})


            }else{
                res.render('login', {errors: 'Username and/or password is incorrect', message:false})
            }
        }).catch(error=>{
            res.render('login', {errors: 'Server Error', message:false})
        })
    }



})

app.post('/SignUp', [
    check('name').exists({checkFalsy: true}).withMessage('You must type your name'),
    check('name').isAlpha('en-US', {ignore: '\s'}).withMessage('The name must contain only letters'),
    check('password').isLength({ min: 8 }).withMessage("Password must have minimum of 8 length"),
    check('email').exists().isEmail().withMessage("Please put a valid email address" )
    //check('password').matches(/\d/).withMessage('Password must contain a number')

],(req,res)=> {
    //Validating the input upon sign-up to stop SQL Injection
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render("signUp", {errors: errors.array()});
    } else {
        /*
            Sanitize the inputs to prevent SQL injection
           The regular expression /[^\w\s]/gi matches any character that is not a word character (alphanumeric) or whitespace,
            and the replace() method replaces these characters with an empty string.
        */
        let password = req.body.password.replace(/[^\w\s]/gi, "");
        console.log(password)
        let email = req.body.email.replace(/[^\w@.-]/gi, "");
        let firstname = req.body.name.replace(/[^\w\s]/gi, "");

        // Generate a salt using bcrypt
        //const saltRounds = 10;
        //const salt = bcrypt.genSaltSync(saltRounds);
        const salt =  crypto.randomBytes(16).toString('hex');
        console.log(salt)
        //Store the salt in a file:
        storePasswordInfo('info/salts.json',{email:email, salt:salt})
        // Generate a pepper using crypto
        const pepper = crypto.randomBytes(16).toString('hex');
        storePasswordInfo('info/pepper.json',{email:email, pepper:pepper})
        console.log(salt)
        // Function to hash a password with salt and pepper
        const saltedPassword = password + salt;
        const pepperedPassword = saltedPassword + pepper;
        const hashedPassword = crypto.createHash('sha256').update(pepperedPassword).digest('hex');
        // Generate a unique verification token for email verification
        const token = crypto.randomBytes(20).toString('hex');
        const creationTime = Date.now();
        // Insert the new user into the "users" table
        const query = {
            text: 'INSERT INTO users (email, password, isverified, verificationtoken, firstname, creationtime) VALUES ($1, $2, $3, $4, $5, $6)',
            values: [email, hashedPassword, false, token, firstname, creationTime]
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
    const currentTime = Date.now()
    const fiveMinutesInMilliseconds = 5 * 60 * 1000;
    const timeDifference = 24 * 60 * 60 * 1000;
    //Check if the token in the link is correct as the one in the database
   const tokenQuery = {
        text: 'SELECT verificationtoken FROM users WHERE email = $1 AND $2 - creationtime < $3',
        values: [email, currentTime,fiveMinutesInMilliseconds] // 24 hours in milliseconds
    };

    pool.query(tokenQuery, (err, result) => {
        if (err) {
            console.log(err);
        } else {
            if (result.rows.length > 0 && token=== result.rows[0].verificationtoken) {
                const updateQuery = {
                    text: 'UPDATE users SET isverified = $1 WHERE email = $2 AND verificationtoken = $3',
                    values: [true, email, token],
                };
                pool.query(updateQuery)
                    .then(()=>{
                        res.render('login', {message: 'Your account has been verified', errors: false})
                    }).catch(err=>console.log(err));
            }else{
                return res.render('verificationError')
            }
        }
    })
})


app.listen(port, () => console.log(`Example app listening on port ${port}!`));



