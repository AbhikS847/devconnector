const epxress = require('express'),  router = epxress.Router();

// @route  GET api/users
// @desc   Test route
// @access Public
router.get('/',(req,res)=>{res.send('Auth route')});

module.exports = router;