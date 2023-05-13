const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());


mongoose.connect('mongodb+srv://khilanpatel15:Hanuman07@todoapp.sto3qsi.mongodb.net/test1?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB', err));


const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});


const User = mongoose.model('User', userSchema);


const auth = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token, 'mysecretkey');
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
};


app.post('/api/register', async (req, res) => {
  if (!req.body || !req.body.name || !req.body.email || !req.body.password) {
    return res.status(400).send('Name, email, and password are required.');
  }

 
  let user = await User.findOne({ email: req.body.email });
  if (user) return res.status(400).send('User already registered.');


  user = new User({
    name: req.body.name,
    email: req.body.email,
    password: await bcrypt.hash(req.body.password, 10)
  });
  await user.save();

 
  const token = jwt.sign({ _id: user._id, name: user.name, email: user.email }, 'mysecretkey');

  res.header('Authorization', token).send({ _id: user._id, name: user.name, email: user.email });
});


app.post('/api/login', async (req, res) => {
  if (!req.body || !req.body.email || !req.body.password) {
    return res.status(400).send('Email and password are required.');
  }


  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send('Invalid email or password.');


  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) return res.status(400).send('Invalid email or password.');


  const token = jwt.sign({ _id: user._id, name: user.name, email: user.email }, 'mysecretkey');

  res.header('Authorization', token).send({ _id: user._id, name: user.name, email: user.email });
});


app.get('/api/user', auth, async (req, res) => {
  const user = await User.findById(req.user._id).select('-password');
  res.send(user);
});

app.get('/api/users', async (req, res) => {
    try {
      const users = await User.find().select('-password');
      res.send(users);
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal server error.');
    }
  });
  
app.listen(port, () => console.log(`Server running on port ${port}`));
