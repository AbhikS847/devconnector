const epxress = require('express'),  router = epxress.Router(), auth = require('../../middleware/auth'), User = require('../../models/User'),
{check, validationResult} = require('express-validator'), jwt = require('jsonwebtoken'), config = require('config'), bcrypt = require('bcryptjs');

// @route  GET api/users
// @desc   Test route
// @access Public
router.get('/', auth , async (req,res)=>{
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }

    catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


router.post('/',[
 check('email','Please include a valid email').isEmail(), check('password','Password is required').exists()
],async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) {return res.status(400).json({errors:errors.array()});}

    const {email, password} = req.body;

    try{
        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({errors:[{msg:'Invalid credentails'}]});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.status(400).json({errors:[{msg:'Invalid credentails'}]});
        }

        const payload = {
            user:{
                id:user.id
            }
        };
        
        jwt.sign(payload, config.get('jwtSecret'), {expiresIn: 360000}, (err,token) => {
            if(err) throw err;
            res.json({token});
        });
    }

    catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});
module.exports = router;