const express = require('express'), app = express(), PORT = process.env.PORT || 5000, connectDB = require('./config/db');

connectDB();

app.get('/',(req,res)=>{res.send("API Running");})

//Init Middleware
app.use(express.json({extended:false}));

//Define Routes
app.use('/api/auth' , require('./routes/api/auth'));
app.use('/api/posts' , require('./routes/api/posts'));
app.use('/api/profile' , require('./routes/api/profile'));
app.use('/api/users' , require('./routes/api/users'));


app.listen(PORT, () => {console.log(`Server started on port ${PORT}`);});

