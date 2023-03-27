require('dotenv').config();

// imports 
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS

const app = express();
app.use(express.json());

//Models
const User = require('./models/User')

//Open Route - public route
app.get('/', (req, res) => {
    res.status(200).json({message: 'OK'});
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]

    if(!token)
        return res.status(401).json({message: 'Invalid token'});
    
    try
    {
        const secret = process.env.SECRET_KEY

        jwt.verify(token, secret)

        next();
    }
    catch (error)
    {
        res.status(400).json({message:'Invalid token'})
    }
}

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id;

    //check if user exists
    const user = await User.findById(id, '-password');

    if(!user)
        return res.status(404).json({message: 'User not found'});
})


app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmPassword } = req.body;

    //validations
    
    if (!name)
        return res.status(422).json({message:"Name is required"});

    if (!email)
        return res.status(422).json({message:"Email is required"});

    if (!password)
        return res.status(422).json({message:"Password is required"});

    if (password !== confirmPassword)
        return res.status(422).json({message:"The passwords do not match"});

    // check if user exists

    const userExists = await User.findOne({ email: email})

    if (userExists)
        return res.status(422).json({message:"Please, use another email"});

    res.status(200).json({user})

    // create password

    const salt = await bcrypt.genSalt(12)
    const passHash = await bcrypt.hash(password, salt)

    //create user

    const user = new User({
        name,
        email,
        password: passHash
    })

    try 
    {
        await user.save()
        res.status(200).json({message:"User saved successfully"});
    } 
    catch (error)
    {
        res.status(500).json({message : error})
    }
})

app.post('/auth/login', async (req, res) =>{
    const { email, password } = req.body;

    //validations

    if (!password)
        return res.status(422).json({message:"Password is required"});

    if (!email)
        return res.status(422).json({message:"Email is required"});

    // check if user exists

    const user = await User.findOne({ email: email})

    if(!user)
        return res.status(422).json({message:"User does not exist"});

    // check i9f password matches

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword)
        return res.status(422).json({message:"Invalid password"});

        
    try 
    {
        const secret = process.env.SECRET_KEY;
        const token = jwt.sign({ id: user._id }, secret);
        res.status(200).json({message: "Login successful"}, token);
    }
    catch (error)
    {
        res.status(500).json({message : error})
    }
        
})


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.xhw4m11.mongodb.net/?retryWrites=true&w=majority`)
.then(()=> {

    app.listen(3000, ()=> console.log('listening on port 3000') )
    console.log('db connected')

}).catch(error => console.log(error))


