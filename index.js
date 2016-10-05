var express     = require('express'),
    bodyParser  = require('body-parser'),
    morgan      = require('morgan'),
    mongoose    = require('mongoose'),
    nJwt        = require('jsonwebtoken'),
    uuid        = require('uuid'),
    fs          = require('fs'),
    parser      = require('xml2json'),
    passwordHash= require('password-hash'),
    config      = require('./config/config'), // defines things in a seperate file to make it look cleaner
    User        = require('./models/user');   // schema to follow for the login database

var app = express();
// C O N F I G U R A T I O N
var port = config.port;
mongoose.connect(config.database);
// unique key for java web tokens for each session
app.set('topSecret', uuid.v4());


// - body parser to get info from POST/URL params
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
// make ./content publically accessible
app.use(express.static('content'));

// - morgan logs requests to console
app.use(morgan('dev'));

// start the server
var server = app.listen(config.port);
console.log('[ * ] - Started NJS server ');
var io = require('socket.io').listen(server);

// listen for the socket.io heartbeat between server and client
io.sockets.on('connection', function(socket) {
  console.log('sending to client');
  socket.emit('news', { content: 'Hello client, I\'m a server\n'});
  socket.on('feedback', function (data) {
    console.log(data);
    //socket.emit('news', { content: 'new - ' + new Date() });
  });  
});


    // let's GET some /
  app.get('/', function(req, res) {
    fs.readFile(config.index, 'utf8', function(err, contents) {
      res.send(contents);
    });
  });

// A login page of some sort /login
app.get('/login', function(req, res) {
  fs.readFile(config.login, 'utf8', function(err, contents) {
    res.send(contents);
  });
});

// A register page of some sort /register
app.get('/register', function(req, res) {
  fs.readFile(config.register, 'utf8', function(err, contents) {
    res.send(contents);
  });
});

// initiate API routing
var apiRoutes = express.Router();

// register new accounts
apiRoutes.post('/register', function(req, res) {
  User.findOne({
    name: req.body.username
  }, function(err, user) {
    if(err) throw err;
    if(!user) {
      var nick = new User({
        name: req.body.username,
        password: passwordHash.generate(req.body.password),
        uuid: uuid.v4(), 
        admin: false
      });
      nick.save(function(err) {
        if(err) throw err;
        console.log('New user '+req.body.username+' created...');
        console.log(req.body.password+' '+passwordHash.generate(req.body.password));
        res.redirect('/login');
      });
    } else {
      console.log('User exists');
      res.redirect('/login');
    }
  });
});



// user authentication API

apiRoutes.post('/login', function(req, res) {
  User.findOne({
    name: req.body.username
  }, function(err, user) {
    if(err) throw err;
    if(!user) {
      // there is no user
      console.log('no user');
      res.redirect('/register');
    } else if(user) {
      if (passwordHash.verify(req.body.password, user.password)) {
        res.redirect('/register');
        console.log('invalid pwd '+user.password);
        console.log(req.body.password+' '+passwordHash.generate(req.body.password));
      } else {
        // if the username and pwd is correct gen a token
        jwt = nJwt.sign(user, app.get('topSecret'), {
          expiresIn: 720
        });
        res.redirect('/api/secret?user='+user.name+'&access_token='+jwt);
      }
    }
  });
});

// ensures everything in /api/ needs to be authenticated
apiRoutes.use(function(req, res, next) {
  // check the header, URL parameters or post parameters for the auth token
  var token = (req.cookies) || (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
  // decode token
  if (token) {
    // verifies secret and checks token
    nJwt.verify(token, app.get('topSecret'), function(err, decoded) {
      if (err) {
        res.redirect('/login');
      } else {
        // everything seems okay.  save to request for use in other routes.
        req.decoded = decoded;
        next();
      }
    });
  } else {
    // there is no token
    fs.readFile(config.reDirect, 'utf8', function(err, contents) {
      return res.status(403).send(contents);
    });
  }
});

apiRoutes.get('/secret', function(req, res) {
  user = User.name;
  console.log(User);
  res.send('<img src=\"http://pngimg.com/upload/duck_PNG5037.png\" height=\"85%\" width=\"85%\"/><p><h1>Hello '+user+'!</h1></p>');
});

// route /api
app.use('/api', apiRoutes);

// middleware 404 message
app.use(function(req,res) {
  fs.readFile(config.notFound, 'utf8', function(err, contents) {
    res.send(contents);
  });
});
