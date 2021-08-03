var express = require('express');
var router = express.Router();
var userModule = require('../modules/user');
var passCatModel = require('../modules/password_category');
var passModel = require('../modules/add_password');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
var getPassCat = passCatModel.find({});
var getAllPass = passModel.find({});

if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  localStorage = new LocalStorage('./scratch');
}

/*middle ware*/

var checkLoginUser = (req,res,next)=>{
  var userToken = localStorage.getItem('userToken');
  try {
    var decoded = jwt.verify(userToken, 'loginTOken');
  } catch(err) {
    res.redirect('/');
  }
  next();
}

var checkEmail = (req,res,next)=>{
  var email=req.body.email;
  var checkexitemail=userModule.findOne({email:email});
  checkexitemail.exec((err,data)=>{
    if(err) throw err;
    if(data) {
    return  res.render('signup', { title: 'Password Management System',msg:'Email Already exits' });

    }
    next();
  });
}

var checkUserName = (req,res,next)=>{
  var userName=req.body.uname;
  var checkexitUserName=userModule.findOne({username:userName});
  checkexitUserName.exec((err,data)=>{
    if(err) throw err;
    if(data) {
    return  res.render('signup', { title: 'Password Management System',msg:'User Name Already exits' });

    }
    next();
  });
}


/* GET home page. */
router.get('/', (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  if(loginUser){
    res.redirect('./dashboard');
  }else{
  res.render('login', { title: 'Password Management System', msg:'' });
  }
});

router.post('/', (req, res, next)=> {
  var username = req.body.uname;
  var password = req.body.password;
  var checkUser = userModule.findOne({username:username});
  
  checkUser.exec((err,data)=>{
    if(err) throw err;
    var getUserID = data._id;
    var getPassword = data.password;
    if(bcrypt.compareSync(password,getPassword)){
      var token = jwt.sign({ userID: getUserID}, 'loginTOken');
      localStorage.setItem('userToken', token);
      localStorage.setItem('loginUser', username);
      res.redirect('/dashboard');
    }else{
      res.render('login', { title: 'Password Managment System' , msg:'Invalid Username or Password'});
    }
  });
  
});

router.get('/dashboard',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');

  res.render('dashboard', { title: 'Password Management System', loginUser:loginUser,msg:'' });
});

router.get('/signup', (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  if(loginUser){
    res.redirect('./dashboard');
  }else{
  res.render('signup', { title: 'Password Management System',msg:'' });
  }
});



router.post('/signup',checkUserName,checkEmail, (req, res, next)=> {
    var username=req.body.uname;
    var email=req.body.email;
    var password=req.body.password;
    var confpassword=req.body.cpassword;
    if(password != confpassword){
      res.render('signup', { title: 'Password Management System', msg:'Password Not Matched!' });
    }else{
      password = bcrypt.hashSync(req.body.password,11);
    var userDetails= new userModule({
      username:username,
      email:email,
      password:password
    }); 
    userDetails.save((err,doc)=>{
      if(err) throw err;
      res.render('signup', { title: 'Password Management System', msg:'User Registered Successfully' });
    });

  }
});

router.get('/passwordCategory',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  getPassCat.exec((err,data)=>{
    if(err) throw err;
  res.render('password_category', { title: 'Password Category', loginUser:loginUser , records:data});
 });
});

router.get('/passwordCategory/delete/:id',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  var passcat_id = req.params.id;
  var passdelete = passCatModel.findByIdAndDelete(passcat_id);
  passdelete.exec((err,)=>{
    if(err) throw err;
  res.redirect('/passwordCategory');
 });
});
router.get('/passwordCategory/edit/:id',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  var passcat_id = req.params.id;
  var getpassCategory = passCatModel.findById(passcat_id);
  getpassCategory.exec((err,data)=>{
    if(err) throw err;
    res.render('edit_pass_category', { title: 'Edit Password Category', loginUser:loginUser , errors:'',success:'', records:data, id:passcat_id});
 });
});
router.post('/passwordCategory/edit',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  var passcat_id = req.body.id;
  var passwordCategory = req.body.passwordCategory;
  var update_passCat = passCatModel.findByIdAndUpdate(passcat_id,{password_category:passwordCategory});
  update_passCat.exec((err,doc)=>{
    if(err) throw err;
    res.redirect('/passwordCategory');
 });
});

router.get('/add-new-category',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
    res.render('addNewCategory', { title: 'Add New Category' , loginUser:loginUser, errors:'',success:''});
  });


router.post('/add-new-category',checkLoginUser, [check('passwordCategory','Enter Password Category Name').isLength({ min: 1 })],
(req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  const errors = validationResult(req);
  if(!errors.isEmpty()){

    res.render('addNewCategory', { title: 'Add New Category' , loginUser:loginUser, errors:errors.mapped(),success:''});
  }else{
    var passCatName = req.body.passwordCategory;
    var passcatDetails = new passCatModel({
      password_category: passCatName
    });

    passcatDetails.save((err,doc)=>{
      if(err) throw err;
      res.render('addNewCategory', { title: 'Add New Category' , loginUser:loginUser, errors:'', success:'Password Category Inserted Successfully!' });
    });

  }

  
});



router.get('/add-new-password',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  getPassCat.exec((err,data)=>{
    if(err) throw err;
    res.render('addNewPassword', { title: 'Add New Password ' , loginUser:loginUser, records:data, success:''});
  });

});

router.post('/add-new-password',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  var pass_cat = req.body.pass_cat;
  var project_name  = req.body.project_name;
  var pass_details = req.body.pass_details;
  var password_details = new passModel({
    password_category:pass_cat,
    project_name:project_name,
    password_details:pass_details,
    

  });
    password_details.save(()=>{
      getPassCat.exec((err,data)=>{
       if(err) throw err;
        res.render('addNewPassword', { title: 'Add New Password ' , loginUser:loginUser, records:data, success:"Password details inserted Successfully"});
      });
    
    });

});



router.get('/view-all-password',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  getAllPass.exec((err,data)=>{
    if(err) throw err;
    res.render('viewAllPassword', { title: 'View All Password', loginUser:loginUser, records:data });
  });
  
});

router.get('/password-detail/edit/:id',checkLoginUser, (req, res, next)=> {
  var loginUser = localStorage.getItem('loginUser');
  var id = req.params.id;
  var getPassDetails = passModel.findById({_id:id});
  getPassDetails.exec((err,data)=>{
    if(err) throw err;
    getPassCat.exec((err,data1)=>{
    res.render('edit_password_detail', { title: 'View All Password', loginUser:loginUser, records:data1, record:data,success:'' });
    });
  });
  
});

router.get('/password-detail',checkLoginUser, (req, res, next)=> {
  res.redirect('/dashboard');
});



router.get('/logout', (req, res, next)=> {
  localStorage.removeItem('userToken');
  localStorage.removeItem('loginUser');
  res.redirect('/');
});

module.exports = router;
