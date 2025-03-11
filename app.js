var express = require('express');
var app = express();
var request1 = require('request');
const { v4: uuidv4 } = require('uuid');
var EventEmitter = require('events').EventEmitter;
var cors = require('cors')
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();
var path = require("path");
var fs = require('fs');
var multer = require('multer');
var timeout = require('connect-timeout');
const http = require('http')
var https = require('https');
const mime = require('mime-types');
const { promisify } = require('util');
var mv = require('mv');
const winlog1 = require("./log/winstonlog1");
const NodeRSA = require('node-rsa');
const axios = require('axios');
const SftpClient = require('ssh2-sftp-client');
const cron = require('node-cron');
var corsOptions = {
  origin: '*',
  optionsSuccessStatus: 200, // For legacy browser support
  methods: "GET, POST, OPTIONS, PUT, PATCH, DELETE"
}
app.use(cors(corsOptions));
const nosniff = require('dont-sniff-mimetype')
const xl1 = require("xlsx");
var CryptoJS = require("crypto-js");

const { sendBadRequestResponse, isMonth, iscurrentdate, isunicids, isYear, sendDatabaseErrorResponse, sendForbiddenResponse, sendNotFoundResponse, validateRequiredAttributes, sendErrorResponse, sendInvalidInputResponse, isAlphanumeric, isValidEmail, isAlphabetic, isAnyCharacter } = require("./utils/errorHandler")

 /**
 * Login APIs namespace.
 
 * @namespace Login_SignUp_Module
 */
/**
 * Preview APIs namespace.
 
 * @namespace Preview_Module
 */

app.use(nosniff())
//---------------------------------VAPT-------------------------------------------

const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'SAMEORIGIN' }));
app.use(helmet())


const { expressCspHeader, NONCE } = require('express-csp-header');

app.use(expressCspHeader({
  directives: {
    'script-src': [NONCE]
  }
}));

app.disable('x-powered-by');
app.use(function (req, res, next) {
  // res.removeHeader("x-powered-by");
  res.setHeader("x-powered-by", "My Server");
  // res.setHeader("X-Content-Type-Options", "nosniff");
  // res.header('X-Frame-Options', 'SAMEORIGIN');

  res.removeHeader('server');
  next();
});


app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));


//-------------------------------------------------------------------------------
// app.use(function (req, res, next) {
//   winlog.info("in use 1")
// //   // Website you wish to allow to connect
//   res.setHeader('Access-Control-Allow-Origin',  '*');
//   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
//   next();
// })


// app.use(function (req, res, next) {

//   // Website you wish to allow to connect
//   res.setHeader('Access-Control-Allow-Origin', '*');

//   // Request methods you wish to allow
//   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

//   // Request headers you wish to allow
//   res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

//   // Set to true if you need the website to include cookies in the requests sent
//   // to the API (e.g. in case you use sessions)
//   res.setHeader('Access-Control-Allow-Credentials', true);

//   // Pass to next layer of middleware
//   next();
// });
var winlog = require("./log/winstonlog");

var UA_route1 = require('./api/web3js/index');
var userSiginUp = require('./api/userSignUp');
var userRole = require('./api/userRole')

var UA_route3 = require('./api/useraccounts')
var UA_loans = require('./api/loans')
var UA_pools = require('./api/pools')
var UA_contract = require('./api/web3js/index');
var UA_excel = require('./api/createexcel')

var ERC20_transfer = require('./api/ERC20/MyToken')

var Attribute = require('./api/addAttributes.js');

var IPFSadd = require('./api/IPFS.js');
var BC_getallpools = require('./api/BCpools');

var updatedeal = require('./api/updatedeal');

var dealOnbording = require('./api/dealOnbording.js');
var dealdoc = require('./api/DealDocument');

var TrancheCommit = require('./api/TrancheInvestCommit')

var loantapecols = require('./api/loantapecolumns.js');
var loansave = require('./api/LoanSaveTest.js')

var paymentsettings = require('./api/InvestorWallet')

var lazerzero = require('./api/LayeZero')
var tranche = require('./api/updatetranche')

var GetTransactionDetails = require('./api/GetUserTransactionDetails')
var SaveUserTransactions = require('./api/SaveTransactionDetails')

var SavePaymentSettingsOffchain = require('./api/PaymentSettingsOffChain')
var TransactionOffchain = require('./api/TransactionDetailsOffchain')
var AccountDetailsOffchain = require('./api/AccountDetailsOffChain')

var pooldoc = require('./api/PoolDocument')
// var preclosing = require('./api/PreClosing')
var exceptionreport = require('./api/Exceptionreport')

//var PreDealData = require('./api/PreDealLoans')
const { updatetranchestatus } = require('./api/updatetranche');
const attributes = require('./api/addAttributes.js');

//var WIP = require('./api/wip')
var Preview = require('./api/Preview')

var loanagg = require('./api/Iaaggregatesummary');
var Ialoanprocess = require('./api/IALoanprocesstape');

var trustee_route = require('./api/IADealCreation.js')
var payingagent = require('./api/Payingagent.js')

var IApayingagent = require('./api/IAPADealCreation.js')
var IADealRecurring = require('./api/IADealRecurring.js')

var IAconsolidated = require('./api/IAConsolidatedsummary.js')
var IAtrustee = require('./api/IATrusteeDeal.js')
const PAdeal = require('./api/IAPADealCreation.js');

const Batch = require('./api/LoanBatch.js');

var Mongoindex = require('./api/config/Mongoindex.js');

var Downtime = require('./api/Downtimepopup.js');

var Wholeloaninvestment = require('./api/WholeLoanInvestment.js');

var PGPEncryptionAndKeyGeneration = require('./api/PGPEncryptionAndKeyGeneration.js');
var HashiCorpVault = require('./api/HashiCorpVault.js');

// Request methods you wish to allow
// res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

// Request headers you wish to allow
//res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

// Set to true if you need the website to include cookies in the requests sent
// to the API (e.g. in case you use sessions)
//res.setHeader('Access-Control-Allow-Credentials', true);
const config = require('./api/config/NetworkConfig');
const ipfsAPI = require('ipfs-api');


//const ipfs = ipfsAPI(config.ipfsURL, '9095', { protocol: 'http' });

var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');
var bearerToken = require('express-bearer-token');
// ------------------------- BC connection ---------------------

const solc = require('solc');
const { get } = require('http');
const Web3 = require('web3');
//const web3 = new Web3("https://api.avax-test.network/ext/bc/C/rpc");

const web3 = new Web3(config.rpcURL);

const SUser = require('./api/abi/User');
const batch = require('./api/LoanBatch.js');
const RolebasedAccess = require('./api/RoleBasedAccess.js');
const downtimepopup = require('./api/Downtimepopup.js');

const contractAddress = SUser.address; // deployed contract address( can be taken from remix or index.js)
// const contractPath = path.resolve(__dirname, 'api', 'contracts', 'User.sol');
// //const source = fs.readFileSync(contractPath, 'utf8');
const privKey = '476645f88bc9ef81a40a45ef84972b8e71944f1bd7080cf2b0d6efdc60ee43e6';  //replcae
const address = '0xC60B683D1835B72A1f3CdAE3ac29b49607F0176D';



//const tempFile = JSON.parse(solc.compile(JSON.stringify(input)));
//winlog.info(tempFile)
//const contractFile = tempFile.contracts['']['User'];
//winlog.info(contractFile)

//const bytecode = contractFile.evm.bytecode.object;
const abi = SUser.abi;

const incrementer = new web3.eth.Contract(abi, contractAddress);

// ---------------------------------------BC connection end-------
/*var privateKey = fs.readFileSync('tls.key', 'utf8');
var certificate = fs.readFileSync('tls.crt', 'utf8');
var credentials = { key: privateKey, cert: certificate };
*/
//---------------- circle api connection
/*
const MessageValidator = require('sns-validator');

const circleArn =
  /^arn:aws:sns:.*:908968368384:(sandbox|prod)_platform-notifications-topic$/

const validator = new MessageValidator()
app.use(function (request, response, next) {
  if (request.url == '/') {

    if (request.method === 'HEAD') {
      response.writeHead(200, {
        'Content-Type': 'text/html',
      })
      response.end(`HEAD request for ${request.url}`)
      winlog.info('Received HEAD request')
      return
    }
    if (request.method === 'POST') {
      let body = ''
      request.on('data', (data) => {
        body += data
      })
      request.on('end', () => {
        winlog.info(`POST request, \nPath: ${request.url}`)
        winlog.info('Headers: ')
        console.dir(request.headers)
        winlog.info(`Body: ${body}`)

        response.writeHead(200, {
          'Content-Type': 'text/html',
        })
        response.end(`POST request for ${request.url}`)
        handleBody(body)
      })
    }
    else {
      winlog.info(request.url)
      const msg = `${request.method} method not supported`
      winlog.info(msg)
      response.writeHead(404, {
        'Content-Type': 'text/html',
      })
      response.end(msg)
      return
    }

    const handleBody = (body) => {
      const envelope = JSON.parse(body)
      validator.validate(envelope, (err) => {
        if (err) {
          console.error(err)
        } else {
          switch (envelope.Type) {
            case 'SubscriptionConfirmation': {
              if (!circleArn.test(envelope.TopicArn)) {
                console.error(
                  `\nUnable to confirm the subscription as the topic arn is not expected ${envelope.TopicArn}. Valid topic arn must match ${circleArn}.`
                )
                break
              }
              request1(envelope.SubscribeURL, (err) => {
                if (err) {
                  console.error('Subscription NOT confirmed.', err)
                } else {
                  winlog.info('Subscription confirmed.')
                }
              })
              break
            }
            case 'Notification': {
              var message = JSON.parse(envelope.Message)
              if (String(message.notificationType) == "payments") {

                winlog.info("Received message for payments: " + JSON.stringify(message))
                winlog.info("message.payment.source.id :  " + message.payment.source.id)
                let resp = paymentsettings.transferUSDCCircle(message, request, response, function (err, body) {
                  if (err)
                    winlog.info(err)
                  winlog.info(body);
                });
              }
              else if (String(message.notificationType) == "transfers" && String(message.transfer.status) == "complete") {

                winlog.info("Received message for transfers: " + JSON.stringify(message))
                winlog.info("USDC minted in investor account successfully")
                return ({
                  "success": true,
                  "message": "USDC minted success"
                })
              }
              else {
                winlog.info("Received message: " + JSON.stringify(message))
                break
              }
            }
            default: {
              console.error(`Message of type ${body.Type} not supported`)
            }
          }
        }
      })
    }
  }
  else {
    winlog.info("Not a circle api !")
    winlog.info("url: " + request.url + "   " + request.method)
    return next();
  }
})
*/

//--------- circle api connection end






//var logoupload = multer({ storage: storage5 }).single('filename');




var xlfilestorage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'uploads');
  },
  filename: function (req, file, callback) {
    callback(null, file.originalname);
  }
});
var documentstorage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'uploads');
  },
  filename: function (req, file, callback) {
    callback(null, file.originalname);
  }
});
var logostorage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'uploads');
  },
  filename: function (req, file, callback) {
    callback(null, file.originalname);
  }
});

var tempfilestorage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'tempfolder');
  },
  filename: function (req, file, callback) {
    callback(null, file.originalname);
  }
});

var documentupload = multer({

  storage: documentstorage,
  fileFilter: function (req, file, cb) {
    var allowedExtensions = ['.xls', '.xlsx', '.pdf', '.doc', '.docx', '.csv', '.txt'];
    var allowedMimeTypes = [
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/csv',
      'text/plain'
    ];

    if (req.originalUrl === "/updateTermsOfService") {

      allowedExtensions = ['.pdf', '.doc', '.docx', '.txt'];
      allowedMimeTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain'
      ];

    }

    const ext = path.extname(file.originalname).toLowerCase();
    const mimeType = file.mimetype;

    if (!allowedExtensions.includes(ext) || !allowedMimeTypes.includes(mimeType)) {
      if (req.originalUrl === "/updateTermsOfService") {
        return cb(new Error("Invalid file type. Only PDF, DOC, DOCX, and TXT are allowed."));
      } else
        return cb(new Error("Invalid file type. Only Excel, PDF, Word, CSV, and TXT files are allowed."));
    }
    cb(null, true);
  }
}).single('filename');




var xlfileupload = multer({

  storage: xlfilestorage,
  fileFilter: function (req, file, cb) {
    const allowedExtensions = ['.xls', '.xlsx'];
    const allowedMimeTypes = [
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    const ext = path.extname(file.originalname).toLowerCase();
    const mimeType = file.mimetype;

    if (!allowedExtensions.includes(ext) || !allowedMimeTypes.includes(mimeType)) {
      return cb(new Error("Invalid file type. Only xls and xlsx are allowed."));
    }
    cb(null, true);
  }
}).single('filename');


var tempfileupload = multer({


  storage: tempfilestorage,
  fileFilter: function (req, file, cb) {
    console.log("PGP:::::")
    var allowedExtensions = ""
    var allowedMimeTypes = ""
    if (req.originalUrl === "/encryptZipFileUsingPgp" || req.originalUrl==="/addencryptedfileinSFTP") {

      allowedExtensions = ['.zip','.pgp'];
      allowedMimeTypes = [
        'application/zip',
        'application/pgp',
        'application/pgp-encrypted',
        'application/pgp-signature'

      ];
    }
    else if (!req.originalUrl === "/UploadLoanTape") {
      allowedExtensions = ['.json', '.keystore'];
      allowedMimeTypes = [
        'application/json',
        'application/octet-stream'
      ];
    }
    else {
      allowedExtensions = ['.xls', '.xlsx'];
      allowedMimeTypes = [
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      ];
    }

    const ext = path.extname(file.originalname).toLowerCase();
    const mimeType = file.mimetype;

    if (!allowedExtensions.includes(ext) || !allowedMimeTypes.includes(mimeType)) {
      if (req.originalUrl === "/encryptZipFileUsingPgp") {
        return cb(new Error("Invalid file type. Only .zip files are allowed.")); cb(null, true);
      }
      else if (!req.originalUrl === "/UploadLoanTape") {
        return cb(new Error("Invalid file type. Only .json and .keystore wallet files are allowed.")); cb(null, true);
      }
      else {
        return cb(new Error("Invalid file type. Only xls and xlsx are allowed."));

      }
    }
    cb(null, true);
  }
}).single('filename');


var logoupload = multer({

  storage: logostorage,
  fileFilter: function (req, file, cb) {
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    const mimeType = file.mimetype;

    if (!allowedExtensions.includes(ext) || !allowedMimeTypes.includes(mimeType)) {
      return cb(new Error("Invalid file type. Only JPG, PNG, WEBP allowed."));
    }
    cb(null, true);
  }
}).single('filename');



var storage1 = multer.diskStorage({
  destination: function (req, file, cb) {
    winlog.info(req.body)
    // winlog.info(req.file.userid)

    //winlog.info(file.userid)
    cb(null, 'uploads/KYC/' + req.body.userid)
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);

  }
});
var upload1 = multer({ storage: storage1 });

//----------------




//--------------------
//--------------------  JWT  ---------------------------------------------------------------------

//set secret variable
app.set('secret', config.JWTSecretKey);
let EndpointtoIgnore = ['/login', '/jwt_token', '/createnewaccount', '/signUp', '/forgotPassword', '/resetPassword', '/upload', '/createUserRole', '/updateTermsOfService', '/GetAllUsersByUserRole', '/getuserbyid', '/setDowntime', '/getDowntime', '/updatepasswordwithhash'];
let testEndPointtoIgnore = ['/logintovault']
EndpointtoIgnore = EndpointtoIgnore.concat(testEndPointtoIgnore);
app.use(expressJWT({
  secret: config.JWTSecretKey, algorithms: ['HS256']
}).unless({ //add testEndPointtoIgnore to ignore jwt token verification
  
  path: EndpointtoIgnore
}));
app.use(bearerToken());

app.use(function (req, res, next) {
  console.log("2::::")
  winlog.info(' ------>>>>>> new request for %s', req.originalUrl);

  // if endpointtoignore contains the requested url, then ignore the jwt token verification
  //console.log(EndpointtoIgnore+" "+req.originalUrl.replace(/(\?.*|#.*)$/, ""))
  req.originalUrl = req.originalUrl.replace(/(\?.*|#.*)$/, "");
  if (EndpointtoIgnore.includes(req.originalUrl)) {
    return next();
  }

  var token = req.token;
  winlog.info(token + "::::token");
  jwt.verify(token, app.get('secret'), function (err, decoded) {
    console.log("1:::")
    if (err) {
      let responseMessage = {
        isSuccess: false,
        statuscode: 401,
        message: ''
      };

      if (err.name === 'TokenExpiredError') {
        responseMessage.message = 'Token is expired';
      } else if (err.name === 'JsonWebTokenError') {
        responseMessage.message = 'Invalid token';
      } else {
        responseMessage.message = 'Failed to authenticate token. Make sure to include the token returned from /jwt_token call in the authorization header as a Bearer token';
      }

      res.status(401).send(responseMessage);
      return;
    } else {
      // add the decoded user name and org name to the request object
      // for the downstream code to use
      req.user = decoded;
      console.log("IN::::::::::::" + JSON.stringify(req.user))
      req.emailid = decoded.emailid;
      //req.password = decoded.password;
      req.Role = decoded.Role;
      req.userId = decoded.userId;
      RolebasedAccess.checkRole(req, res, next);
      // console.log(req.Role==="Verification")
      // console.log("IN::::::::::::" + JSON.stringify(req.user))
      // //  winlog.info(util.format('Decoded from JWT token: emailid - %s, password - %s', decoded.emailid, decoded.Role));
      // if (req.Role === "Issuer" || req.role==="Verification") {
      //   console.log("INside if:")
      //   RolebasedAccess.checkRole(req, res, next);
      // }
      // else{
      //   return next();
      // }
    }
  });
});


app.use(function (err, req, res, next) {
  winlog.info("error " + JSON.stringify(err))
  if (err.name === 'UnauthorizedError' && err.message === "No authorization token was found") {
    winlog.warn("UnauthorizedError")
    var responseMessage = {
      "isSuccess": false,
      "statuscode": 401,
      "message": "Unauthorized: No authorization token was found."
    }
    winlog1('warn').warn(JSON.stringify(responseMessage))
    return res.status(401).send(responseMessage);

  }
  else if (err.name === 'UnauthorizedError' && err.message === "jwt expired") {
    winlog.warn("TokenExpiredError")
    var responseMessage = {
      "isSuccess": false,
      "statuscode": 401,
      "message": "Token Expired,Please log in again to continue."
    }
    winlog1('warn').warn(JSON.stringify(responseMessage))
    return res.status(401).send(responseMessage);
  }
  else if (err.name === "UnauthorizedError") {

    winlog.warn("UnauthorizedError")
    var responseMessage = {
      "isSuccess": false,
      "statuscode": 401,
      "message": "Unauthorized: Please log in again to continue."
    }
    winlog1('warn').warn(JSON.stringify(responseMessage))
    return res.status(401).send(responseMessage);
  } else {
    next()
  }
});


function getErrorMessage(field) {
  var response = {
    success: false,
    message: field + ' field is missing or Invalid in the request'
  };
  return response;
}

//handled
//Fixed unit test case
// Register and enroll user
/**
 *
 * Authenticates a user with the provided credentials.
 *
 * @function login - POST
 * @memberof Login_SignUp_Module
 * @param {string} req.body.EmailId - The user's email address.
 * @param {string} req.body.Password - The user's password.
 * @param {string} req.body.Role - The user's role.
 * @returns {Json} This function sends a JSON response.
 *
 * @example
 * // Example output:
 * {
 *   "statuscode": 200,
 *   "isSuccess": true,
 *   "message": "User Authentication Successful",
 *   "result": {},
 *   "token": "eyJhbGciOiJIUzI1NiIsInR..."
 * }
 */

app.post('/login', jsonParser, async function (req, res) {

  //--------------------------------
  const requiredAttributes = ['EmailId', 'Password', 'Role'];
  const source = 'body';

  if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
    return; // The response has already been sent by sendBadRequestResponse
  }
  if (!isAlphabetic(req.body.Role)) {
    sendErrorResponse(res, "Please enter a valid Role");
    return;
  }
  if (!isValidEmail(req.body.EmailId)) {
    sendErrorResponse(res, "Please enter a valid Email");
    return;
  }


  req.body.EmailId = req.body.EmailId.toLowerCase();

  var EmailId = req.body.EmailId;
  var Password = req.body.Password;

  if (!EmailId) {
    res.json(getErrorMessage('\'EmailId\''));
    return;
  }
  if (!Password) {
    res.json(getErrorMessage('\'Password\''));
    return;
  }
  let errcount = 0;
  const get1 = async () => {

    winlog.info(`Making a call to contract at address ${contractAddress}`);
    var status = 'Active'
    try {
      var data = await incrementer.methods
        .getUserByEmailAndStatusAnduserRole(EmailId, status, req.body.Role)
        .call({ from: address });
      winlog.info(`The current string is: ${data}`);
      winlog.info("data:: " + JSON.stringify(data));
    } catch (e) {
      errcount++;
      if (errcount <= 3) {
        winlog.info("error occ" + e);
        get1();
      } else {
        var r = { "statuscode": 500, "isSuccess": false, "message": e.message }
        res.status(500).send(r);
      }
    }
    var arr1 = JSON.parse(JSON.stringify(data));
    var resData = [];
    //for (var i = 0; i < arr1.length; i++) {
    // var resp = arr1[i].split("#");
    if (arr1.length > 0) {

      var c = {
        "UserId": arr1[0][0],
        "EmailAddress": arr1[0][1],
        "UserHash": arr1[0][2],
        "UserSatus": arr1[0][3],
        "UserAccAddress": arr1[0][4],
        "UserRole": arr1[0][5],
        "UserName": arr1[0][6],
        "TermsOfService": arr1[0][13]

      };
      var token = jwt.sign({
        //exp: Math.floor(Date.now() / 1000) + (60 * 60),  // 1 hr
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24 hours
        EmailId: EmailId,
        Role: arr1[0][5],
        "userId": arr1[0][0]
      }, app.get('secret'));
      //  let response =  helper.getRegisteredUser(emailid, password, true);




      IPFSadd.getFileFromIPFSUsingFetch(arr1[0][2], function (err, response) {
        if (err) {
          var responseMessage = {
            "isSuccess": false,
            "statuscode": 500,
            "message": "Internal server Error"
          }
          winlog1('warn').warn(JSON.stringify(responseMessage))
          return res.status(500).send(responseMessage);
        }
        const ipfsData = response;
        ipfsData.UserId = arr1[0][0];
        // ipfsData.UserSatus = arr1[0][3];
        ipfsData.UserAccAddress = arr1[0][4];

        ipfsData.KycVerifiedStatus = arr1[0][11]
        ipfsData.KycUploadStatus = arr1[0][12]
        ipfsData.TermsOfService = arr1[0][13]
        ipfsData.VAToken = arr1[0][18]
        ipfsData.IAToken = arr1[0][19] ? arr1[0][19] : ""

        //ipfsData.logo = arr1[0][18]?"/uploads/" + arr1[0][18]:""
        //ipfsData.logo = ""
        const file1 = path.resolve(__dirname + '/uploads/' + ipfsData.UserId + ".png");
        console.log("IN:::::")
        const bytes = CryptoJS.AES.decrypt(
          Password,
          config.AESDecryptionKey
        );
        Password = JSON.parse(
          bytes.toString(CryptoJS.enc.Utf8)
        );

        // let Passworddata = userSiginUp.sha512(Password, ipfsData.PwdSalt);
        // Password = Passworddata.passwordHash;
        // console.log(Password + " " + ipfsData.Password)
        if (ipfsData.EmailAddress == EmailId && ipfsData.Password == Password) {
          winlog.info("login sucess" + JSON.stringify(ipfsData));
          delete ipfsData["Password"];
          delete ipfsData["confirmPassword"];
          var r = {
            "statuscode": 200,
            "isSuccess": true,
            "message": "User Authentication Successful",
            "result": ipfsData,
            "token": token
          }

          if (ipfsData.logo) {
            console.log("in:::")
            https.get(config.ipfsGetURL + ipfsData.logo, (response) => {


              console.log("data fetched")
              const writeStream = fs.createWriteStream(file1);

              response.pipe(writeStream);

              writeStream.on("finish", () => {
                writeStream.close();

                winlog.info("Download file ready!");
                //res.send({"filepath":'/uploads/'+filename})
                r.result.logo = '/uploads/' + ipfsData.UserId + ".png"
                res.send(r);

              })
            }).on('error', (err) => {
              console.error('Error fetching file from IPFS:', err);
            });
          } else {
            console.log("out:::")

            r.result.logo = ""
            res.send(r);
          }


        } else {
          var responseMessage = {
            "isSuccess": false,
            "statuscode": 201,
            "message": "Please enter Valid Credentials"
          }
          winlog1('warn').warn(JSON.stringify(responseMessage))
          return res.status(201).send(responseMessage);
        }

      })


    } // end of if 
    else {
      var responseMessage = {
        "isSuccess": false,
        "statuscode": 201,
        "message": "Please enter Valid EmailID"
      }
      winlog1('warn').warn(JSON.stringify(responseMessage))
      return res.status(201).send(responseMessage);
    }

  };
  get1();
  //--------------------------

});


app.get('/jwt_token', jsonParser, async function (req, res) {


  var baseData = req.headers.authorization.split(' ');
  let data = baseData[1];
  let buff = Buffer.from(data, 'base64'); //new Buffer(data, 'base64');

  let text = buff.toString('ascii');

  let originalData = text.split(':');
  var EmailId = originalData[0];
  var Password = originalData[1];

  //how to generate base64 format data
  var base64data = new Buffer("robin@uprootsecurity.com:D&4eKbxtfNNp").toString('base64');
  console.log("base64data::" + base64data);

  winlog.info(EmailId + " :email");
  winlog.info(Password + " :password");
  if (!EmailId) {
    res.json(getErrorMessage('\'EmailId\''));
    return;
  }
  if (!Password) {
    res.json(getErrorMessage('\'Password\''));
    return;
  }
  let errcount = 0;
  const get1 = async () => {

    winlog.info(`Making a call to contract at address ${contractAddress}`);
    var status = 'Active'
    try {
      var data = await incrementer.methods
        .getUserByEmailAndStatus(EmailId, status)
        .call({ from: address });
      winlog.info(`The current string is: ${data}`);
      winlog.info("data:: " + JSON.stringify(data));
    } catch (e) {
      errcount++;
      if (errcount <= 3) {
        winlog.info("error occ" + e);
        get1();
      } else {
        var r = { "statuscode": 500, "isSuccess": false, "message": e.message }
        res.status(500).send(r);
      }
    }
    var arr1 = JSON.parse(JSON.stringify(data));
    var resData = [];
    //for (var i = 0; i < arr1.length; i++) {
    // var resp = arr1[i].split("#");
    winlog.info(arr1.length);
    if (arr1.length > 0) {

      var c = {
        "UserId": arr1[0][0],
        "EmailAddress": arr1[0][1],
        "UserHash": arr1[0][2],
        "UserSatus": arr1[0][3],
        "UserAccAddress": arr1[0][4],
        "UserRole": arr1[0][5],
        "UserName": arr1[0][6],
        "TermsOfService": arr1[0][13]

      };
      var token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),  // 24 hr
        EmailId: EmailId,
        Role: arr1[0][5],
        "userId": arr1[0][0]
      }, app.get('secret'));
      //  let response =  helper.getRegisteredUser(emailid, password, true);


      IPFSadd.getFileFromIPFSUsingFetch(arr1[0][2], function (err, response) {
        if (err) {
          var responseMessage = {
            "isSuccess": false,
            "statuscode": 500,
            "message": "Internal server Error"
          }
          winlog1('warn').warn(JSON.stringify(responseMessage))
          return res.status(500).send(responseMessage);
        }
        const ipfsData = response;
        ipfsData.UserId = arr1[0][0];
        // ipfsData.UserSatus = arr1[0][3];
        ipfsData.UserAccAddress = arr1[0][4];

        // let Passworddata = userSiginUp.sha512(Password, ipfsData.PwdSalt);
        // Password = Passworddata.passwordHash;
        if (ipfsData.EmailAddress == EmailId && ipfsData.Password == Password) {
          winlog.info("login sucess");
          delete ipfsData["Password"];
          ipfsData.KycVerifiedStatus = arr1[0][11]
          ipfsData.KycUploadStatus = arr1[0][12]
          ipfsData.TermsOfService = arr1[0][13]
          var r = { "jwt_token": token }
          res.send(r);
        } else {
          var r = { "message": "Password is incorrect" }
          res.status(204).send(r);
        }
        //  res.send(file.content.toString('utf8'));


      })


    } // end of if 
    else {
      var r = { "message": "Username is incorrect" }
      res.status(204).send(r);
    }

  };
  get1();
  //--------------------------

});
// ---------------------------------------------------------------------------------------------------



app.post('/upload', upload1.any(), function (req, res, next) {
  winlog.info(JSON.stringify(req.files));

  let response = userSiginUp.updateuserKYC(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

  // res.send(req.files);
});




app.post('/createnewaccount', jsonParser, function (req, res) {

  let response = UA_route3.createuser(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/getprivatekey', jsonParser, function (req, res) {

  let response = UA_route3.GetPrivateKey(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//unused
app.post('/deploy', jsonParser, function (req, res) {

  let response = UA_route1.deploycontract(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


// const ipfsAPI = require('ipfs-api');


// const ipfs = ipfsAPI('104.42.155.78', '5001', { protocol: 'http' })

//Fixed unit test case
app.post('/createUserRole', jsonParser, function (req, res) {

  let response = userRole.createUserRole(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.get('/GetAllUserRoles', jsonParser, function (req, res) {

  let response = userRole.GetAllUserRoles(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
//Fixed unit test case
//Addfile router for adding file a local file to the IPFS network without any local node
app.post('/signUp', jsonParser, function (req, res) {


  let response = userSiginUp.signUp(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

// app.post('/login', jsonParser, function (req, res) {

//   let response = userSiginUp.login(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });

// })
//Fixed unit test case
app.get('/forgotPassword', jsonParser, function (req, res) {

  let response = userSiginUp.forgotPassword(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})


//Fixed unit test case
app.post('/resetPassword', jsonParser, function (req, res) {

  let response = userSiginUp.resetPassword(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

//Getting the uploaded file via hash code.
app.get('/getipfscontent', function (validCID) {

  //This hash is returned hash of addFile router.
  //const validCID = 'QmTdihZUGi2GwuHdiMHidGehKHd8zaekNBSwjWeCiVkboq'

  ipfs.files.get(validCID, function (err, files) {
    files.forEach((file) => {
      winlog.info(file.path)
      winlog.info(file.content.toString('utf8'))
      var ipfsData = JSON.parse(file.content.toString('utf8'));
      return ipfsData;
    })
  })

})

//loans onboard
//Fixed unit test case
app.post('/uploadloanlms', function (req, res) {


  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      xlfileupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

          var filename = req.file.originalname;

          var output = { "statuscode": 200, "isSuccess": true, filename: req.file.filename, filetype: ext.toString(), "Message": "Document uploaded successfully!" };
          res.send(output);

        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })
});
//Fixed unit test case
app.post('/onboardloans', jsonParser, function (req, res) {

  let response = UA_loans.fetchkeysofonboardedloans(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

//Fixed unit test case
app.get('/getallloans', jsonParser, function (req, res) {

  let response = UA_loans.getallloans(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

// app.get('/getloansbyarayofloanhashes', jsonParser, function (req, res) {

//   let response = UA_loans.getloansbyarayofloanhashes(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });

// })

//Fixed unit test case
app.get('/updateLoanStatus', jsonParser, function (req, res) {

  let response = UA_loans.updateLoanStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

app.post('/updatedatas', jsonParser, function (req, res) {

  let response = UA_loans.updatedata(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.post('/exportexcel', jsonParser, function (req, res) {

  let response = UA_excel.createexcel(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.post('/deploycontract', jsonParser, async function (req, res) {

  var contractname = "CreatePool";
  let response = await UA_contract.deploycontract(req, res, contractname, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

//poolcreation
// app.post('/createpool', jsonParser, async function (req, res) {

//    let response1 = UA_pools.createpool(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
//   // }
// });

//Fixed unit test case
app.post('/createpool', jsonParser, function (req, res) {

  let response1 = UA_pools.createpool(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

//not used
app.get('/getallpools', jsonParser, function (req, res) {

  let response = UA_pools.getallpools(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/getbypoolid', jsonParser, function (req, res) {

  let response = UA_pools.getbypoolid(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


//Fixed unit test case
app.get('/getallpoolsbyIssuerId', jsonParser, function (req, res) {

  let response = UA_pools.getallpoolsbyIssuerId(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/getallpoolsbyVAId', jsonParser, function (req, res) {

  let response = UA_pools.getallpoolsbyVAId(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


app.get('/updatePoolStatus', jsonParser, function (req, res) {

  let response = UA_pools.updatePoolStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/updateLoanAndPoolStatus', jsonParser, function (req, res) {

  let response = UA_pools.updateLoanAndPoolStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/GetAllUsersByUserRole', jsonParser, function (req, res) {
  let response = userSiginUp.GetAllUserByUserRole(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/filterloans', jsonParser, function (req, res) {

  let response = UA_loans.filterloans(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/updateArrayofLoanStatus', jsonParser, function (req, res) {

  let response = UA_loans.updateArrayofLoanStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})
//Fixed unit test case
app.post('/mappoolstoloans', jsonParser, function (req, res) {

  let response = UA_pools.mappoolstoloans(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

// app.post('/ProcessBDB', jsonParser, function (req, res) {

//   let response = UA_pools.processLoans(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// })

//not used
app.post('/ERC20', jsonParser, function (req, res) {

  let response = ERC20_transfer.transfer(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//handled
app.post('/NFTmint', jsonParser, function (req, res) {

  let response = IPFSadd.addfile(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


app.post('/addAttribute', jsonParser, function (req, res) {

  let response = Attribute.addAttribute(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.get('/getAllAttributes', jsonParser, function (req, res) {

  let response = Attribute.getAllAttributes(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.get('/getAttributeDetailsByPoolId', jsonParser, function (req, res) {

  let response = Attribute.getAttributeDetailsByPoolId(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.get('/getallpoolsfrombc', jsonParser, function (req, res) {

  let response = BC_getallpools.querygetallpools(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
    //res.send(body);
  });
})
//handled
app.get('/getpoolsfrombcbyissuer', jsonParser, function (req, res) {

  let response = BC_getallpools.getallpoolsbyissuerid(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})
//handled
//Fixed unit test case
app.get('/getpoolsfrombcbyunderwriter', jsonParser, function (req, res) {

  let response = BC_getallpools.getallpoolsbyunderwriterid(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})
//handled
app.post('/updatepoolstatusbc', jsonParser, function (req, res) {

  let response = BC_getallpools.updatepoolstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})


app.post('/deletepool', jsonParser, function (req, res) {

  let response = UA_pools.deletepool(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//handled //pool to deal
app.post('/createDeal', jsonParser, function (req, res) {

  let response1 = dealOnbording.createDeal(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });


});

//handled
//Fixed unit test case 
app.post('/updatedealstatus', jsonParser, function (req, res) {

  let response1 = dealOnbording.updatedealstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });


});

/*
//handled
//Fixed unit test case // this for underwriter xl upload
app.post('/updatedeal', jsonParser, function (req, res) {

  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });


    }
    else {
      upload(req, res, function (err) {
        if (err) {
          return res.status(403).send({
            statuscode: 403,
            isSuccess: false,
            message: "Error uploading file",
          });
          return res.end("Error uploading file.");
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);
          if (ext !== ".xlsx" && ext !== ".xls") {
            var responseMessage = {
              "isSuccess": false,
              "statuscode": 415,
              "filetype": ext.toString(),
              "message": "Document Should contain only Excel / LMS file"
            }
            winlog1('warn').warn(JSON.stringify(responseMessage))
            return res.status(415).send(responseMessage);
          }

          var filename = req.file.originalname;

          var output = { "statuscode": "200", "isSuccess": true, filename: req.file.filename, filetype: ext.toString(), "Message": "Document uploaded successfully!" };
          let response1 = updatedeal.updateDeal(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });

        } else {
          const response = { statuscode: 404, isSuccess: false, message: 'File not found' };

          res.status(response.statuscode).json({ isSuccess: response.isSuccess, message: response.message });

        }

      });
    }
  });
});*/

//handled
app.get('/getDealsByUnderwriterId', jsonParser, function (req, res) {

  let response = dealOnbording.getDealsByUnderwriterId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})

//handled
//Fixed unit test case
app.get('/getDealDetailsByDealId', jsonParser, function (req, res) {

  let response = dealOnbording.getDealDetailsByDealId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

//handled
app.post('/addDealDocuments', jsonParser, function (req, res) {

  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });

    }
    else {
      documentupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

          //var filename = req.file.originalname;

          // var output = { isSuccess: true, filename: req.file.filename, filetype: ext.toString(), result: "Document uploaded successfully!" };
          let response1 = dealdoc.addDeal(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });

        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })


});


//handled
app.post('/updateDealDocument', jsonParser, function (req, res) {
  let response1 = dealdoc.updatedeal(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

app.get('/downloadDealTemplate', (req, res) => {

  var filepath = path.join(__dirname + '/uploads/demo_deal_template.xlsx');

  if (fs.existsSync(filepath)) {
    winlog.info("filepath in xlsx for download: " + filepath);

    res.status(200).download(filepath)
  }
  else {
    res.send({ "statuscode": 404, "isSuccess": false, "message": "no file found" });
  }
});

//handled
app.get('/getInvestorDealDetailsByDealId', jsonParser, function (req, res) {

  let response = dealOnbording.getInvestorDealDetailsByDealId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});
//handled
app.get('/getcommitmentdetails', jsonParser, function (req, res) {

  let response = TrancheCommit.GetTrancheCommitment(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

//handled
//Fixed unit test case
app.get('/getAllDeals', jsonParser, function (req, res) {

  let response = dealOnbording.getAllDeals(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

app.get('/getAllDealsByInvestorId', jsonParser, function (req, res) {

  let response = dealOnbording.getAllDealsByInvestorId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});


//handled
//Fixed unit test case
app.get('/getDealsbyServicerId', jsonParser, function (req, res) {

  let response = dealOnbording.getDealsbyServicerId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);

  });
});
//handled
// app.get('/getDealsbyPayingagentId', jsonParser, function (req, res) {

//   let response = dealOnbording.getDealsbyPayingagentId(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     winlog.info("in")
//     res.send(body);
//   });
// });

//handled
app.post('/InvesmentCommit', jsonParser, function (req, res) {
  let response1 = TrancheCommit.EditCommit(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.post('/EditCommit', jsonParser, function (req, res) {
  let response1 = TrancheCommit.EditCommit(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//handled
app.post('/Invest', jsonParser, function (req, res) {
  let response1 = TrancheCommit.Invest(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

// app.get('/getcommitmentdetails', jsonParser, function (req, res) {

//   let response = TrancheCommit.GetTrancheCommitment(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     winlog.info("in")
//     res.send(body);
//   });
// });
//handled
app.get('/DealDetailsRedirect', jsonParser, function (req, res) {

  let response = dealOnbording.getscreendetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});
//handled
app.post('/uploadapproach', jsonParser, function (req, res) {
  let response1 = dealOnbording.uploadapproach(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.get('/datequery', jsonParser, function (req, res) {
  let response1 = dealOnbording.datequery(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.post('/dateanalyse', jsonParser, function (req, res) {
  let response1 = dealOnbording.dateanalyse(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
// app.post('/uploadservicerreport', function (req, res) {

//   fs.access("tempfolder", function (error) {
//     if (error) {
//       res.status(404).send('Directory Does Not exist!');
//       winlog.info("Directory Does Not exist!");
//     }
//     else {
//       upload2(req, res, function (err) {
//         if (err) {
//           return res.end("Error uploading file.");
//         }
//         winlog.info("__dirname::: " + __dirname);
//         winlog.info(req.file);
//         if (String(req.file) != "undefined") {

//           var uploadpath = __dirname + '/tempfolder/' + req.file.filename;
//           //filenamearr.push(uploadpath);
//           winlog.info(uploadpath);

//           var ext = path.extname(req.file.originalname);
//           winlog.info("extension :::" + ext);

//           var filename = req.file.originalname;

//           //rename the file
//           var oldfilename = filename;
//           var month = String(req.body.month).padStart(2, '0')
//           // if (parseInt(req.body.month) < 10) {
//           //   var month = "0" + req.body.month;
//           // }
//           // else {
//           //   var month = req.body.month;
//           // }
//           winlog.info("req.body.dealid: " + req.body.dealid)

//           var docname = req.body.dealid + "-" + month + "-" + req.body.year + ext;
//           winlog.info("docname::: " + docname);
//           winlog.info("oldfilename:: " + oldfilename);
//           fs.rename(__dirname + '/tempfolder/' + oldfilename, __dirname + '/tempfolder/' + docname, function (err) {
//             if (err) winlog.info('ERROR: ' + err);
//           });

//           //copying file from tempfolder to uploads
//           mv(__dirname + '/tempfolder/' + docname, __dirname + '/servicerUploads/' + docname, function (err) {
//             if (err) { throw err; }
//             winlog.info('file moved successfully');
//           });

//           var output = { isSuccess: true, month: req.body.month, year: req.body.year, filename: docname, filetype: ext.toString(), result: "Document uploaded successfully!" };
//           winlog.info("output: " + JSON.stringify(output))
//           if (output.isSuccess) {
//             let response = dealOnbording.datesave(req, res, function (err, body) {
//               if (err)
//                 res.send(err);
//               res.send(body);
//             });
//           }
//           // res.send(output);

//         } else {
//           res.sendStatus(204);
//         }

//       });
//     }
//   })

// });

//handled
// app.get('/showcolumns', upload, function (req, res) {
//   let response = loantapecols.displaycolumns(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });

// //handled
// app.post('/savemapping', jsonParser, async function (req, res) {
//   let response1 = await loantapecols.savemapping(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });

//   if (response1.success) {

//     setTimeout(function () {
//       winlog.info("inside loantape saving!!!!")
//       // var testFolder = "/home/monisha/Downloads/rsakeystore/";
//       var testFolder = path.join(__dirname + '/uploads/')
//       var count = 0;
//       filenames = fs.readdirSync(testFolder);
//       filenames.forEach(file => {
//         var extension = path.extname(file);
//         var File = path.basename(file, extension);
//         //winlog.info(File+" "+req.body.dealid)
//         if (File == req.body.dealid + "-public-key") {
//           winlog.info("user already exist::::::")
//           count = 1;
//         }
//       });

//       if (count == 0) {
//         winlog.info("Creating new private and public key for the user::::::::::")
//         var key1 = new NodeRSA({ b: 1024 });//1024
//         var public_key = key1.exportKey('public');
//         var private_key = key1.exportKey('private')
//         // var testFolder = "/home/monisha/Downloads/rsakeystore/";
//         var testFolder = path.join(__dirname + '/uploads/')
//         //write private and public key
//         fs.writeFileSync(testFolder + req.body.dealid + "-public-key.txt", public_key);
//         fs.writeFileSync(testFolder + req.body.dealid + "-private-key.txt", private_key);
//         winlog.info("done")
//       }
//       loansave.createDeal(req, res, (err, body) => {
//         if (err)
//           res.send(err)
//         res.send(body)
//       })
//     }, 2000)
//   }
//   else {
//     res.send({ "success": false, "message": "servicer aggregation already saved for this month/year" })
//   }
// });


app.get('/viewservicerdatadb', jsonParser, function (req, res) {
  let response1 = loansave.viewservicerdatadb(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//handled
app.post('/saveservicerdata', jsonParser, function (req, res) {
  let response1 = loansave.saveservicerdata(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//handled //not used
app.post('/saveDealDetailsbyDealIdPostClosing', jsonParser, function (req, res) {
  let response1 = dealOnbording.saveDealDetailsbyDealIdPostClosing(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

//handled
app.get('/getDealDetailsbyDealIdPostClosing', jsonParser, function (req, res) {
  let response1 = dealOnbording.getDealDetailsbyDealIdPostClosing(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
//Fixed unit test case
app.get('/getPreviousDealDetails', jsonParser, function (req, res) {
  let response1 = dealOnbording.getPreviousDealDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.get('/getDealDetailsbyInvIdPostClosing', jsonParser, function (req, res) {
  let response1 = dealOnbording.getDealDetailsbyInvIdPostClosing(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//hanlded
//Fixed unit test case
app.get('/getAllInvestmentsByInvId', jsonParser, function (req, res) {
  let response1 = dealOnbording.getAllInvestmentsByInvId(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.post('/SavePaymentSettings', jsonParser, async function (req, res) {
  let response = paymentsettings.AddDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.get('/getwiretransferdetails', jsonParser, async function (req, res) {
  let response = paymentsettings.GetWireTransferDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.post('/transferUSDCtoInvestor', jsonParser, async function (req, res) {
  let response = paymentsettings.transferUSDC(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.post('/layerzerosendmessage', jsonParser, async function (req, res) {
  let response = lazerzero.Sendmessage(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
//Fixed unit test case
app.get('/getDealsByIssuerId', jsonParser, function (req, res) {

  let response = dealOnbording.getDealsByIssuerId(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})
//handled
app.post('/updatetranchestatus', jsonParser, async function (req, res) {
  let response = tranche.updatetranchestatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

// app.get('/get', jsonParser, function (req, res) {
//   let response1 = dealOnbording.get(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });

// app.post('/save', jsonParser, function (req, res) {
//   let response1 = dealOnbording.save(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });

//handled
app.post('/updateDealreviewstatus', jsonParser, function (req, res) {

  let response1 = dealOnbording.updatereviewdealstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });


});
//handled
app.get('/getservicertransactiondetails', jsonParser, function (req, res) {

  let response1 = GetTransactionDetails.GetServicerTransactionDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.post('/transferUSDCtoServicer', jsonParser, function (req, res) {

  let response1 = GetTransactionDetails.USDCMint(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.post('/SaveTransactionDetails', jsonParser, function (req, res) {

  let response1 = SaveUserTransactions.SaveTransactionDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//handled
app.get('/getAllInvestorInvestmentsbyDealID', jsonParser, function (req, res) {

  let response1 = dealOnbording.getAllInvestorInvestmentsByDealID(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled
app.get('/getalltransactions', jsonParser, function (req, res) {

  let response1 = SaveUserTransactions.GetAllTransactions(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//handled

app.get('/getpayingagenttransactiondetails', jsonParser, function (req, res) {

  let response1 = GetTransactionDetails.GetPayingagentTransactionDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/testNFT', jsonParser, function (req, res) {

  let response = IPFSadd.addfile(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


//handled
app.post('/updateUSDCtransferstatus', jsonParser, function (req, res) {

  let response = dealOnbording.updateUSDCtransferstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//handled
app.get('/servicerRedirect', jsonParser, function (req, res) {

  let response = dealOnbording.servicerRedirect(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//handled
app.get('/getdealstatusbydealid', jsonParser, function (req, res) {
  let response = dealOnbording.getdealstatusbydealid(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})

//Fixed unit test case
app.get('/getAttributesByPoolName', jsonParser, function (req, res) {

  let response = Attribute.getAttributesByPoolName(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.get('/mapAttributesToPool', jsonParser, function (req, res) {

  let response = Attribute.mapAttributesToPool(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/savebankdetailsoffchain', jsonParser, function (req, res) {

  let response = SavePaymentSettingsOffchain.AddDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getUserOffchainBankDetails', jsonParser, function (req, res) {

  let response = SavePaymentSettingsOffchain.GetOffChainDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/savetransactiondetailsoffchain', jsonParser, function (req, res) {

  let response = TransactionOffchain.SaveTransactionDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/updatetransactiondetailsoffchain', jsonParser, function (req, res) {

  let response = TransactionOffchain.UpdateTransactionDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


app.get('/gettransactiondetailsoffchainbydealid', jsonParser, function (req, res) {

  let response = TransactionOffchain.GetTransactionOffChainDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/addaccountdetailsoffchain', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.AddAccountOffChain(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/updateaccountsoffchain', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.UpdateAccountOffChain(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


app.get('/getaccountdetailsbydealidoffchain', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.GetAccountOffChainDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//update on-chain /off-chain and update commit vs invest
//Fixed unit test case
app.post('/updatepaymentmode', jsonParser, function (req, res) {

  let response = dealOnbording.updatepaymentmode(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getinvestorsoffchainwiredetails', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.GetInvestorOffChainWireDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getserviceroffchainwiredetails', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.GetServicerOffChainWireDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getpayingagentoffchainwiredetails', jsonParser, async function (req, res) {

  let response = await AccountDetailsOffchain.GetPayingAgentOffChainWireDetails(req, res, function (err, body) {
    winlog.info("inside err")

    if (err)
      res.send(err);
    res.send(body);
  });
  res.send(response)
})
//Fixed unit test case
app.get('/getAllInvestorCommitmentsbyDealID', jsonParser, function (req, res) {

  let response1 = dealOnbording.getAllInvestorCommitmentsByDealID(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/InvestOffchain', jsonParser, function (req, res) {
  let response1 = TrancheCommit.InvestOffChain(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

app.post('/trustee/senddatatoIA', jsonParser, function (req, res) {
  let response = IAtrustee.SendDatatoIA(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


// app.post('/senddatatoIA', jsonParser, function (req, res) {
//   let response1 = TrancheCommit.InvestOffChain(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });

// });



// app.post('/Modifyaccountbalanceoffchain', jsonParser, function (req, res) {
//   let response1 = AccountDetailsOffchain.Modifyaccountbalanceoffchain(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });

// })




app.post('/testtransaction', jsonParser, function (req, res) {

  let response = TransactionOffchain.testtransaction(req, res, function (err, body) {

    if (err)
      res.send(err);
    res.send(body);
  });
})

//api to update PA and servier off-chain transfer status
app.post('/updatepostclosingscreenstatus', jsonParser, function (req, res) {

  let response = dealOnbording.updatepostclosingscreenstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//handled
app.post('/deletetransactiondetailsoffchain', jsonParser, function (req, res) {

  let response = TransactionOffchain.deletetransactiondetailsoffchain(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/deleteaccountsoffchain', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.DeleteAccountOffChain(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//api to update invoker
app.post('/grantrole', jsonParser, function (req, res) {

  let response = userRole.grantrole(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getaccountdetailsbydealidoffchainpendingtransaction', jsonParser, function (req, res) {

  let response = AccountDetailsOffchain.IncludePendingTransaction(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/updateKYCStatus', jsonParser, function (req, res) {


  let response = userSiginUp.updateKYCVerifiedStatus(req, res, function (err, body) {

    if (err)
      res.send(err);
    res.send(body);


  })

})
//Fixed unit test case
app.get('/getuserbyid', jsonParser, function (req, res) {

  let response = userSiginUp.GetUserbyID(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//Fixed unit test case
app.post('/approvetranche', jsonParser, function (req, res) {


  let response = tranche.approveTranche(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

app.post('/approvetranchebywalletfile', function (req, res) {
  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/tempfolder/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

          let response = tranche.approveTranche(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });


          // var output = { isSuccess: true, filename: req.file.filename, filetype: ext.toString(), result: "Document uploaded successfully!" };
          // res.send(output);

        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })
});

// app.post('/deleteloans', jsonParser, function (req, res) {

//   winlog.info("deleteloans api started");
//   let response = UA_loans.deleteloans(req, res, function (err, body) {

//     if (err)
//       res.send(err);
//     res.send(body);
//   });

// })

app.get('/DownloadIPFSFile', jsonParser, function (req, res) {

  let response = dealdoc.DownloadDealDoc(req, res, function (err, body) {

    if (err)
      res.send(err);
    res.send(body);
  });

})


//Fixed unit test case
app.post('/addPoolDocument', jsonParser, function (req, res) {
  // const requiredAttributes = ['filename'];
  // const source = 'file'; 

  // if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse,source)) {
  //   return; // The response has already been sent by sendBadRequestResponse
  // }
  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      documentupload(req, res, function (err) {
        if (err) {

          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);
          // if (ext !== ".xlsx" && ext !== ".xls") {
          //   var responseMessage = {
          //     "isSuccess": false,
          //     "statuscode": 415,
          //     "filetype": ext.toString(),
          //     "message": "Document Should contain only Excel / LMS file"
          //   }
          //   winlog1('warn').warn(JSON.stringify(responseMessage))
          //   return res.status(415).send(responseMessage);
          // }

          //var filename = req.file.originalname;

          // var output = { isSuccess: true, filename: req.file.filename, filetype: ext.toString(), result: "Document uploaded successfully!" };
          let response1 = pooldoc.addPoolDoc(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });

        } else {
          const response = { statuscode: 404, isSuccess: false, message: 'File not found' };

          res.status(response.statuscode).json({ isSuccess: response.isSuccess, message: response.message });

        }

      });
    }
  })

});

app.get('/getPoolDocument', jsonParser, function (req, res) {

  let response = pooldoc.getPoolDocument(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})
// app.post('/encrypt',function(){
// var CryptoJS = require("crypto-js");
// function a(){
//   var ciphertext = CryptoJS.AES.encrypt(JSON.stringify("1234"), 'ALtReKQqUH1VTh43vNomog==').toString();
//   winlog.info(ciphertext)
// }
// a()

// })



// Function to download the payAgents details as excel sheet
app.get('/downloadpayagentdetails', jsonParser, async function (req, res) {
  let response = await AccountDetailsOffchain.GetPayingAgentOffChainWireDetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);

    //  res.send (response);
  });

  await UA_excel.downloadExcel(req, res, response, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});

app.post('/updatepooldocuments', jsonParser, function (req, res) {

  winlog.info('step1')
  let response = pooldoc.updatepooldocuments(req, res, function (err, body) {
    winlog.info('step2')
    if (err)
      res.send(err);
    winlog.info('step3')
    res.send(body);
  });

})
//Fixed unit test case
app.get('/DownloadPoolDoc', jsonParser, function (req, res) {

  let response = pooldoc.DownloadPoolDoc(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/getFileListByDealName', jsonParser, function (req, res) {

  let response = UA_loans.getFileListByDealName(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

// app.get('/testupdatepoolname', jsonParser, function (req, res) {

//   let response = UA_pools.test(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });


/**
 *
 * Uploads and updates a user's logo.
 *  @instance
 * @function addLogo - POST
 * @memberof Login_SignUp_Module
 * @param {string} req.body.userid - The ID of the user.
 * @param {file} req.file - The uploaded logo file.
 * @returns {Json} This function sends a JSON response.
 *
 * @example
 * // Example output:
 * {
 *   "statuscode": 200,
 *   "isSuccess": true,
 *   "message": "User Update Success",
 *   "file": {}
 * }
 */

app.post('/addlogo', jsonParser, function (req, res) {

  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {

      logoupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);

        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);


          let response = userSiginUp.updateLogo(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });
        } else {
          return res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }
      })
    }
  })
  // res.send(req.files);
});

app.post('/DeleteDealDocument', jsonParser, function (req, res) {

  winlog.info('step1')
  let response = dealdoc.DeleteDealDoc(req, res, function (err, body) {
    winlog.info('step2')
    if (err)
      res.send(err);
    winlog.info('step3')
    res.send(body);
  });

})

app.post('/deletePoolDocument', jsonParser, function (req, res) {

  winlog.info('step1')
  let response = pooldoc.DeletePoolDoc(req, res, function (err, body) {
    winlog.info('step2')
    if (err)
      res.send(err);
    winlog.info('step3')
    res.send(body);
  });

});
//Fixed unit test case
app.get('/getAItrainedPoolNames', jsonParser, function (req, res) {
  winlog.info('step1')
  let response = UA_pools.getbypoolname(req, res, function (err, body) {
    winlog.info('step2')
    if (err)
      res.send(err);
    winlog.info('step3')
    res.send(body);
  });
});

app.post('/aitraunedname', jsonParser, function (req, res) {

  let response = UA_pools.addaitrainednames(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/exceptionReport', jsonParser, function (req, res) {

  console.log("latest")
  let response = exceptionreport.createexcel(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})



//--------------------------------------------------

app.get('/querystandardfieldnames', jsonParser, function (req, res) {
  let response = Preview.querystandardfieldnames(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.post('/previewsavemapping', jsonParser, function (req, res) {
  let response = Preview.processTape(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.post('/downloadpreviewstdloantape', jsonParser, function (req, res) {
  let response = Preview.downloadexcelwithroundoff(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.post('/updatePool', jsonParser, function (req, res) {
  let response = UA_pools.updatePool(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/previewquerypoolmappingdetails', jsonParser, function (req, res) {
  let response = Preview.querypoolmapping(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.post('/previewdeleteloans', jsonParser, function (req, res) {
  let response = Preview.deleteloans1(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/previewunderwriterpool', jsonParser, function (req, res) {
  let response1 = Preview.previewunderwriterpool(req, res, function (err, body) {

    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.post('/previewupdatePoolStatus', jsonParser, function (req, res) {

  let response = Preview.previewupdatePoolStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.post('/savefeedback', jsonParser, function (req, res) {
  let response1 = Preview.savefeedback(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.get('/retrievefeedback', jsonParser, function (req, res) {

  let response = Preview.retrievefeedback(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/previewinvestorpool', jsonParser, function (req, res) {
  let response1 = Preview.previewinvestorpool(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.post('/updatepreviewinvestorlist', jsonParser, function (req, res) {

  let response = UA_pools.updatepreviewinvestorlist(req, res, function (err, body) {
    if (err)

      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get('/getOriginatorlist', jsonParser, function (req, res) {

  let response = Preview.GetOriginator(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

//Fixed unit test case
app.post('/updateVerificationTemplate', jsonParser, function (req, res) {

  let response = Preview.UpdateVerificationTemplate(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

// app.post('/updateVerificationTemplate', jsonParser, function (req, res) {

//   let response = Preview.UpdateVerificationTemplate(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     winlog.info("in")
//     res.send(body);
//   });
// });

//Fixed unit test case
app.get('/getverficationtemplatedetails', jsonParser, function (req, res) {

  let response = attributes.getallAitrainedPoolName(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

//------------------internaluse-------------------
app.post('/editissuerid', jsonParser, function (req, res) {

  let response = Preview.editissuerid(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});


/**
 *
 * Updates the Terms of Service document.
 *
 * @function updateTermsOfService - POST
 * @memberof Login_SignUp_Module
 * @param {file} req - The Express request file object.
 * @returns {Json} This function sends a JSON response.
 *
 * @example
 * // Example output:
 * {
 *   "statuscode": 200,
 *   "isSuccess": true,
 *   "message": "Terms of Service updated successfully",
 *   "result": {}
 * }
 */

app.post('/updateTermsOfService', jsonParser, function (req, res) {

  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {

      documentupload(req, res, function (err) {
        if (err) {

          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);

        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);


          let response = userSiginUp.updateTermsOfService(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });

        } else {
          console.log("inside elsee:::")
          let response = userSiginUp.updateTermsOfService(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });
        }
      })
    }
  })
})
//Fixed unit test case
app.get('/getnotificationlist', jsonParser, function (req, res) {

  let response = Preview.notificationlist(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

app.post('/updateAttributes', jsonParser, function (req, res) {

  let response = Attribute.updateAttributes(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/updatereadlist', jsonParser, function (req, res) {

  let response = Preview.updaterreadlist(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/MoveVAcontractfiles', jsonParser, function (req, res) {

  let response = UA_pools.MoveVAcontractfiles(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//Fixed unit test case
app.get("/fetchVAToken", jsonParser, function (req, res) {
  let response = UA_pools.fetchVAToken(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post("/updateVAcertificate", jsonParser, function (req, res) {
  let response = UA_pools.updateVAcertificate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post("/downloadVAcertificate", jsonParser, function (req, res) {
  let response = UA_pools.downloadVAcertificate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/UploadLoanTape', function (req, res) {

  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, async function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }


        const requiredAttributes = ['DealName', 'Month', 'Year', 'ServicerName'];
        const source = 'body';

        if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
          return; // The response has already been sent by sendBadRequestResponse
        }
        if (!isYear(req.body.Year)) {
          sendErrorResponse(res, "Please enter a valid Year");
          return;
        }
        if (!isAnyCharacter(req.body.DealName)) {
          sendErrorResponse(res, "Please enter a valid DealName");
          return;
        }
        if (!isMonth(req.body.Month)) {
          sendErrorResponse(res, "Please enter a valid Month");
          return;
        }

        winlog.info(req.file);
        if (String(req.file) != "undefined") {
          var ext = path.extname(req.file.originalname);
          var oldfilename = req.file.originalname;
          var docname = req.body.DealName + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName + ext;

          fs.rename(__dirname + '/tempfolder/' + oldfilename, __dirname + '/tempfolder/' + docname, function (err) {
            if (err) winlog.info('ERROR: ' + err);
          });

          //copying file from tempfolder to uploads
          mv(__dirname + '/tempfolder/' + docname, __dirname + '/uploads/' + docname, function (err) {
            if (err) { throw err; }
            winlog.info('file moved successfully');
          });
          var output = {
            "statuscode": 200,
            isSuccess: true,
            month: req.body.Month,
            year: req.body.Year,
            filename: docname,
            filetype: ext.toString(),

            "result": "Document uploaded successfully!"
          };

          await loanagg.updateAggDB(req)
          res.send(output);
        }
        else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }
      })
    }
  });
});
//Fixed unit test case
app.get('/PreviewLoanTape', async (req, res) => {

  const requiredAttributes = ['DealName', 'Month', 'Year', 'ServicerName'];
  const source = 'query';

  if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
    return; // The response has already been sent by sendBadRequestResponse
  }
  if (!isYear(req.query.Year)) {
    sendErrorResponse(res, "Please enter a valid Year");
    return;
  }
  if (!isMonth(req.query.Month)) {
    sendErrorResponse(res, "Please enter a valid Month");
    return;
  }
  if (!isAnyCharacter(req.query.DealName)) {
    sendErrorResponse(res, "Please enter a valid DealName");
    return;
  }
  if (!isAnyCharacter(req.query.ServicerName)) {
    sendErrorResponse(res, "Please enter a valid ServicerName");
    return;
  }
  else {
    var DealName = req.query.DealName;
    var Month = req.query.Month;
    var Year = req.query.Year;
    var ServicerName = req.query.ServicerName;

    var file1 = DealName + "-" + Month + "-" + Year + "-" + ServicerName + ".xlsx";
    var file2 = DealName + "-" + Month + "-" + Year + "-" + ServicerName + ".xls";
    var filepath1 = path.join(__dirname + '/uploads/' + file1);
    var filepath2 = path.join(__dirname + '/uploads/' + file2);
    console.log(filepath1)
    if (fs.existsSync(filepath1)) {
      var file = filepath1
    }
    else if (fs.existsSync(filepath2)) {
      var file = filepath2
    }
    try {
      console.log("in")
      var workbook = xl1.readFile(file, { cellDates: true, dateNF: 'yyyy-mm-dd' });
      var sheet_name_list = workbook.SheetNames;
      var data = await xl1.utils.sheet_to_json(workbook.Sheets[sheet_name_list[0]], { raw: false, defval: "" });

      winlog.info("date length: " + JSON.stringify(data[0]) + "     " + data.length);

      // if (data.length > 500) {
      //     data = data.slice(0, 500);
      // }
      // else if (data.length == 0) {
      //     // var output = { isSuccess: false, result: "Error, Please upload correct excel file" };
      //     // res.send(output);
      //     data = [];
      // }
      // var output = { isSuccess: true, result: data };
      // res.send(output);
      if (data) {
        var output = {
          "statuscode": 200,
          "isSuccess": true,
          "result": data
        };
        res.send(output);
      }
      else {
        var output = {
          "statuscode": 404,
          "isSuccess": false,
          "message": "Error, Please upload correct excel file"
        };
        res.send(output);
      }
    }
    catch (err) {
      var output = {
        "statuscode": 403,
        "isSuccess": false, "message": "Please upload the file again"
      };
      res.send(output);
    }
  }
});

//Fixed unit test case
app.post('/iasaveloanprocessdate', jsonParser, function (req, res) {
  let response = loanagg.saveloanprocessdate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.get('/StdfieldsQuery', jsonParser, function (req, res) {

  let response = loanagg.StdfieldsQuery(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case   
app.get('/getMapping', jsonParser, function (req, res) {
  let response = loanagg.getMapping(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/saveMapping_old', jsonParser, async function (req, res) {
  let response1 = await loanagg.saveMapping(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
  console.log(response1)
  if (response1.isSuccess) {

    setTimeout(async function () {
      var testFolder = path.join(__dirname + '/uploads/key/')
      var count = 0;
      filenames = fs.readdirSync(testFolder);
      filenames.forEach(file => {
        var extension = path.extname(file);
        var File = path.basename(file, extension);
        var docname = req.body.DealName + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName;
        console.log("docname::: " + docname);

        if (File == docname + "-public-key") {
          console.log("user already exist::::::")
          count = 1;
        }
      });
      if (count == 0) {
        console.log("Creating new private and public key for the user::::::::::")
        var key1 = new NodeRSA({ b: 1024 });//1024
        var public_key = key1.exportKey('public');
        var private_key = key1.exportKey('private')
        var testFolder = path.join(__dirname + '/uploads/key/')
        var docname = req.body.DealName + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName;
        console.log("docname::: " + docname);
        //write private and public key
        fs.writeFileSync(testFolder + docname + "-public-key.txt", public_key);
        fs.writeFileSync(testFolder + docname + "-private-key.txt", private_key);
        console.log("done")
      }
      let response = await Ialoanprocess.processTape(req, res, function (err, body) {
        if (err)
          res.send(err);
        res.send(body);
      });
    }, 2000);
  }
  else {
    res.send({ "statuscode": 200, "isSuccess": false, "message": "Loantape data not saved!" })
  }
});

app.post('/saveMapping', jsonParser, async function (req, res) {
  let ClosingTape = req.body.ClosingTape
  console.log(ClosingTape)
  if (ClosingTape == undefined) {
    ClosingTape = 'false';
  } else {
    ClosingTape = String(ClosingTape)
  }
  if (ClosingTape == 'false') {
    console.log("iside save mapping")
    var response1 = await loanagg.saveMapping(req, res, function (err, body) {
      if (err)
        res.send(err);
      res.send(body);
    });
  } else {
    var response1 = await loanagg.saveClosingTapeMapping(req, res, function (err, body) {
      if (err)
        res.send(err);
      res.send(body);
    });
  }
  console.log({ response1 })
  if (response1.isSuccess) {

    setTimeout(async function () {
      if (ClosingTape == 'false') {
        var testFolder = path.join(__dirname + '/uploads/key/')
        var count = 0;
        filenames = fs.readdirSync(testFolder);
        filenames.forEach(file => {
          var extension = path.extname(file);
          var File = path.basename(file, extension);
          var docname = req.body.DealName + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName;
          console.log("docname::: " + docname);

          if (File == docname + "-public-key") {
            console.log("user already exist::::::")
            count = 1;
          }
        });
        if (count == 0) {
          console.log("Creating new private and public key for the user::::::::::")
          var key1 = new NodeRSA({ b: 1024 });//1024
          var public_key = key1.exportKey('public');
          var private_key = key1.exportKey('private')
          var testFolder = path.join(__dirname + '/uploads/key/')
          var docname = req.body.DealName + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName;
          console.log("docname::: " + docname);
          //write private and public key
          fs.writeFileSync(testFolder + docname + "-public-key.txt", public_key);
          fs.writeFileSync(testFolder + docname + "-private-key.txt", private_key);
          console.log("done")
        }
      } else {
        var testFolder = path.join(__dirname + '/closinguploads/key/')
        var count = 0;
        filenames = fs.readdirSync(testFolder);
        filenames.forEach(file => {
          var extension = path.extname(file);
          var File = path.basename(file, extension);
          var docname = req.body.DealName;
          console.log("docname::: " + docname);

          if (File == docname + "-public-key") {
            console.log("user already exist::::::")
            count = 1;
          }
        });
        if (count == 0) {
          console.log("Creating new private and public key for the user::::::::::")
          var key1 = new NodeRSA({ b: 1024 });//1024
          var public_key = key1.exportKey('public');
          var private_key = key1.exportKey('private')
          var testFolder = path.join(__dirname + '/closinguploads/key/')
          var docname = req.body.DealName;
          console.log("docname::: " + docname);
          //write private and public key
          fs.writeFileSync(testFolder + docname + "-public-key.txt", public_key);
          fs.writeFileSync(testFolder + docname + "-private-key.txt", private_key);
          console.log("done")
        }
      }
      let response2 = await Ialoanprocess.processTape(req, res, function (err, body) {
        if (err)
          res.send(err);
        res.send(body);
      });
      console.log({ response2 })
      // if (response2.isSuccess) {
      //   // res.send({ 'isSuccess': response2.isSuccess, "Result": response2.message })
      //   // if (req.body.DealName == "JPMorgan AG - Offerpad SPE Borrower A, LLC" || req.body.DealName == "Validation Tests P1") {
      //   //     let response = await facilitiesprocess.MainTabCalculation(req, res, function (err, body) {
      //   //         console.log('body postgres response::::')
      //   //         console.log(body)
      //   //     });
      //   // }
      // }
    }, 2000);
  }
  else {
    res.send({ "Success": false, "Result": "Loantape data not saved!" })
  }
});


app.get('/PreviewMappedFields', (req, res) => {


  let response = loanagg.previewMappedFields(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.post('/Summarize', jsonParser, function (req, res) {
  let response = loanagg.prepareAggregateSummary(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test case
app.post('/saveaggregatesummarytobc', jsonParser, function (req, res) {
  let response = trustee_route.saveaggregatesummarytobc(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//SERVICER API FOR CF DEAL


app.post('/UploadClosingLoanTape', function (req, res) {


  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, async function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }


        const requiredAttributes = ['DealName'];
        const source = 'body';

        if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
          return; // The response has already been sent by sendBadRequestResponse
        }
        // if (!isYear(req.body.Year)) {
        //   sendErrorResponse(res, "Please enter a valid Year");
        //   return;
        // }
        if (!isAnyCharacter(req.body.DealName)) {
          sendErrorResponse(res, "Please enter a valid DealName");
          return;
        }
        // if (!isMonth(req.body.Month)) {
        //   sendErrorResponse(res, "Please enter a valid Month");
        //   return;
        // }

        winlog.info(req.file);
        console.log({ DealNameee: req.body.DealName })


        if (String(req.file) != "undefined") {
          var ext = path.extname(req.file.originalname);
          var oldfilename = req.file.originalname;
          var docname = req.body.DealName + ext;

          fs.rename(__dirname + '/tempfolder/' + oldfilename, __dirname + '/tempfolder/' + docname, function (err) {
            if (err) winlog.info('ERROR: ' + err);
          });

          //copying file from tempfolder to uploads
          mv(__dirname + '/tempfolder/' + docname, __dirname + '/closinguploads/' + docname, function (err) {
            if (err) { throw err; }
            winlog.info('file moved successfully');
          });
          // var output = { isSuccess: true, filename: docname, filetype: ext.toString(), result: "Document uploaded successfully!" };
          var output = {
            "statuscode": 200,
            isSuccess: true,
            filename: docname,
            filetype: ext.toString(),
            "result": "Document uploaded successfully!"
          };

          res.send(output);
        }
        else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }
      })
    }
  });
});

app.post('/UploadLoanTapeCF', function (req, res) {


  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, async function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }


        const requiredAttributes = ['DealName', 'Month', 'Year', 'ServicerName', 'activity_day', 'activity_type'];
        const source = 'body';

        if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
          return; // The response has already been sent by sendBadRequestResponse
        }
        if (!isYear(req.body.Year)) {
          sendErrorResponse(res, "Please enter a valid Year");
          return;
        }
        if (!isAnyCharacter(req.body.DealName)) {
          sendErrorResponse(res, "Please enter a valid DealName");
          return;
        }
        if (!isMonth(req.body.Month)) {
          sendErrorResponse(res, "Please enter a valid Month");
          return;
        }
        if (!isAnyCharacter(req.body.activity_day)) {
          sendErrorResponse(res, "Please enter a valid Activity Day");
          return;
        }
        if (!isAnyCharacter(req.body.activity_type)) {
          sendErrorResponse(res, "Please enter a valid Activity Type");
          return;
        }

        winlog.info(req.file);
        console.log({ DealNameee: req.body.DealName })
        console.log({ activity_day: req.body.activity_day })
        console.log({ Month: req.body.Month })

        if (String(req.file) != "undefined") {
          var ext = path.extname(req.file.originalname);
          var oldfilename = req.file.originalname;
          var docname = req.body.DealName + "-" + req.body.activity_day + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName + "-" + req.body.activity_type + ext;


          fs.rename(__dirname + '/tempfolder/' + oldfilename, __dirname + '/tempfolder/' + docname, function (err) {
            if (err) winlog.info('ERROR: ' + err);
          });

          //copying file from tempfolder to uploads
          mv(__dirname + '/tempfolder/' + docname, __dirname + '/uploads/' + docname, function (err) {
            if (err) { throw err; }
            winlog.info('file moved successfully');
          });
          var output = {
            "statuscode": 200,
            isSuccess: true,
            month: req.body.Month,
            year: req.body.Year,
            filename: docname,
            filetype: ext.toString(),
            activity_day: req.body.activity_day,
            activity_type: req.body.activity_type,
            "result": "Document uploaded successfully!"
          };

          await loanagg.updateAGGDB_CF(req)
          res.send(output);
        }
        else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }
      })
    }
  });
});

app.get('/PreviewLoanTapeCF', async (req, res) => {


  const requiredAttributes = ['DealName', 'Month', 'Year', 'ServicerName', 'activity_day', 'activity_type'];
  const source = 'query';

  if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
    return; // The response has already been sent by sendBadRequestResponse
  }
  if (!isYear(req.query.Year)) {
    sendErrorResponse(res, "Please enter a valid Year");
    return;
  }
  if (!isMonth(req.query.Month)) {
    sendErrorResponse(res, "Please enter a valid Month");
    return;
  }
  if (!isAnyCharacter(req.query.DealName)) {
    sendErrorResponse(res, "Please enter a valid DealName");
    return;
  }
  if (!isAnyCharacter(req.query.ServicerName)) {
    sendErrorResponse(res, "Please enter a valid ServicerName");
    return;
  }
  if (!isAnyCharacter(req.body.activity_day)) {
    sendErrorResponse(res, "Please enter a valid Activity Day");
    return;
  }
  if (!isAnyCharacter(req.body.activity_type)) {
    sendErrorResponse(res, "Please enter a valid Activity Type");
    return;
  }
  else {


    var DealName = req.query.DealName;
    let ClosingTape = req.body.ClosingTape
    if (ClosingTape == undefined) {
      ClosingTape = 'false';
    } else {
      ClosingTape = String(ClosingTape)
    }
    if (ClosingTape == 'false') {
      var Month = req.query.Month;
      var Year = req.query.Year;
      var ServicerName = req.query.ServicerName;
      var file1 = DealName + "-" + req.query.activity_day + "-" + Month + "-" + Year + "-" + ServicerName + "-" + req.query.activity_type + ".xlsx";
      var file2 = DealName + "-" + req.query.activity_day + "-" + Month + "-" + Year + "-" + ServicerName + "-" + req.query.activity_type + ".xls";
      var filepath1 = path.join(__dirname + '/uploads/' + file1);
      var filepath2 = path.join(__dirname + '/uploads/' + file2);
    } else {
      var file1 = DealName + ".xlsx";
      var file2 = DealName + ".xls";
      var filepath1 = path.join(__dirname + '/closinguploads/' + file1);
      var filepath2 = path.join(__dirname + '/closinguploads/' + file2);
    }


    console.log(filepath1)

    if (fs.existsSync(filepath1)) {
      var file = filepath1
    }
    else if (fs.existsSync(filepath2)) {
      var file = filepath2
    }
    try {
      console.log("in")
      var workbook = xl1.readFile(file, { cellDates: true, dateNF: 'yyyy-mm-dd' });
      var sheet_name_list = workbook.SheetNames;
      var data = await xl1.utils.sheet_to_json(workbook.Sheets[sheet_name_list[0]], { raw: false, defval: "" });

      winlog.info("date length: " + JSON.stringify(data[0]) + "     " + data.length);

      // if (data.length > 500) {
      //     data = data.slice(0, 500);
      // }
      // else if (data.length == 0) {
      //     // var output = { isSuccess: false, result: "Error, Please upload correct excel file" };
      //     // res.send(output);
      //     data = [];
      // }
      // var output = { isSuccess: true, result: data };
      // res.send(output);
      if (data) {
        var output = {
          "statuscode": 200,
          "isSuccess": true,
          "result": data
        };
        res.send(output);
      }
      else {
        var output = {
          "statuscode": 404,
          "isSuccess": false,
          "message": "Error, Please upload correct excel file"
        };
        res.send(output);
      }
    }
    catch (err) {
      var output = {
        "statuscode": 403,
        "isSuccess": false, "message": "Please upload the file again"
      };
      res.send(output);
    }
  }
});

app.post('/saveMappingCF', jsonParser, async function (req, res) {
  let ClosingTape = req.body.ClosingTape
  if (ClosingTape == undefined) {
    ClosingTape = 'false';
  } else {
    ClosingTape = String(ClosingTape)
  }

  if (ClosingTape == 'false') {
    var response1 = await loanagg.saveMapping_CF(req, res, function (err, body) {
      if (err)
        res.send(err);
      res.send(body);
    });
  } else {
    var response1 = await loantapecols.saveClosingTapeMapping(req, res, function (err, body) {
      if (err)
        res.send(err);
      res.send(body);
    });
  }
  //  response1 = { statuscode: 200, isSuccess: true, Result: 'Mapping saved' }

  console.log({ response1 })
  if (response1.isSuccess) {

    setTimeout(async function () {
      if (ClosingTape == 'false') {
        var testFolder = path.join(__dirname + '/uploads/key/')
        var count = 0;
        filenames = fs.readdirSync(testFolder);
        filenames.forEach(file => {
          var extension = path.extname(file);
          var File = path.basename(file, extension);
          var docname = req.body.DealName + "-" + req.body.activity_day + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName + "-" + req.body.activity_type;
          console.log("docname::: " + docname);

          if (File == docname + "-public-key") {
            console.log("user already exist::::::")
            count = 1;
          }
        });
        if (count == 0) {
          console.log("Creating new private and public key for the user::::::::::")
          var key1 = new NodeRSA({ b: 1024 });//1024
          var public_key = key1.exportKey('public');
          var private_key = key1.exportKey('private')
          var testFolder = path.join(__dirname + '/uploads/key/')
          var docname = req.body.DealName + "-" + req.body.activity_day + "-" + req.body.Month + "-" + req.body.Year + "-" + req.body.ServicerName + "-" + req.body.activity_type;
          console.log("docname::: " + docname);
          //write private and public key
          fs.writeFileSync(testFolder + docname + "-public-key.txt", public_key);
          fs.writeFileSync(testFolder + docname + "-private-key.txt", private_key);
          console.log("done")
        }
      } else {
        var testFolder = path.join(__dirname + '/closinguploads/key/')
        var count = 0;
        filenames = fs.readdirSync(testFolder);
        filenames.forEach(file => {
          var extension = path.extname(file);
          var File = path.basename(file, extension);
          var docname = req.body.DealName;
          console.log("docname::: " + docname);

          if (File == docname + "-public-key") {
            console.log("user already exist::::::")
            count = 1;
          }
        });
        if (count == 0) {
          console.log("Creating new private and public key for the user::::::::::")
          var key1 = new NodeRSA({ b: 1024 });//1024
          var public_key = key1.exportKey('public');
          var private_key = key1.exportKey('private')
          var testFolder = path.join(__dirname + '/closinguploads/key/')
          var docname = req.body.DealName;
          console.log("docname::: " + docname);
          //write private and public key
          fs.writeFileSync(testFolder + docname + "-public-key.txt", public_key);
          fs.writeFileSync(testFolder + docname + "-private-key.txt", private_key);
          console.log("done")
        }
      }
      let response2 = await Ialoanprocess.processTapeCF(req, res, function (err, body) {
        if (err)
          res.send(err);
        res.send(body);
      });
      console.log({ response2 })
      if (response2.isSuccess) {
        res.send({ 'isSuccess': response2.isSuccess, "Result": response2.message })
        // if (req.body.DealName == "JPMorgan AG - Offerpad SPE Borrower A, LLC" || req.body.DealName == "Validation Tests P1") {
        //   let response = await facilitiesprocess.MainTabCalculation(req, res, function (err, body) {
        //     console.log('body postgres response::::')
        //     console.log(body)
        //   });
        // }
      }
    }, 2000);
  }
  else {
    res.send({ "statuscode": 200, "isSuccess": false, "message": "Loantape data not saved!" })
  }
});
app.get('/PreviewMappedFieldsCF', (req, res) => {


  let response = loanagg.previewMappedFieldsCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
app.post('/SummarizeCF', jsonParser, function (req, res) {
  let response = loanagg.prepareAggregateSummaryCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/saveaggregatesummarytobcCF', jsonParser, function (req, res) {
  let response = trustee_route.saveaggregatesummarytobcCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

//Fixed unit test case
app.get('/viewaggregatesummaryCF', jsonParser, function (req, res) {
  let response = trustee_route.viewaggregatesummaryCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/consolidatedaggregatesummarytodbCF', jsonParser, function (req, res) {
  let response = IAconsolidated.consolidatedaggregatesummarytodbCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/consolidatedaggregatesummarytobcCF', jsonParser, function (req, res) {
  let response = IAconsolidated.consolidatedaggregatesummarytobcCF(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});
//Fixed unit test caseF
app.get('/previewratingagencypool', jsonParser, function (req, res) {
  let response1 = Preview.getallpoolsbyratingagency(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.get('/getallratingagencypool', jsonParser, function (req, res) {
  let response1 = UA_pools.getallpoolsbyratingagency(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

});
//Fixed unit test case
app.get('/getDealsByRatingagencyId', jsonParser, function (req, res) {

  let response = dealOnbording.getDealsByRatingagency(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
})
let isSavePublishedReportRunning = false;
cron.schedule('* * * * *', async () => {
  console.log("inside scheduler");

  if (process.env.NODE_ENV == "test") {

    let response = UA_pools.updateVAcertificate();
  }
  try {


    let response = UA_pools.updateVAcertificate();

    let respone2 = PAdeal.editDealcreation();

    if (isSavePublishedReportRunning) {
      console.log("SavePublishedReport is already running, skipping this execution.");
    } else {
      // Set the flag to indicate SavePublishedReport is running
      isSavePublishedReportRunning = true;
      try {
        let response3 = await PAdeal.SavePublishedReport();
        console.log("SavePublishedReport task completed:", response3);
      } catch (error) {
        console.error("Error occurred during SavePublishedReport:", error);
      } finally {
        // Reset the flag after the task is complete
        isSavePublishedReportRunning = false;
      }
    }


  } catch (error) {
    console.error("Error connecting to SFTP or updating certificate:", error);
  }
  // } else {
  console.log("out:");

  // }
});
/**
 *
 * Downloads the user's logo.
 *
 * @function downloadLogo - POST
 * @memberof Login_SignUp_Module
 * @param {string} req.body.userid - The ID of the user.
 * @returns {Json} This function either triggers a file download or sends a JSON response if the logo is not found.
 *
 * @example
 * {
 *   "statuscode": 200
 *  File will be downloaded 
 * }
  */
//Fixed unit test case
app.post('/downloadlogo', jsonParser, function (req, res) {
  const requiredAttributes = ['userid'];
  const source = 'body';

  if (validateRequiredAttributes(requiredAttributes, req, res, sendBadRequestResponse, source)) {
    return; // The response has already been sent by sendBadRequestResponse
  }

  var filepath = path.join(__dirname + '/uploads/' + req.body.userid + '.png');

  if (fs.existsSync(filepath)) {
    winlog.info("filepath in xlsx for download: " + filepath);

    res.download(filepath)
  }
  else {
    res.send({ "statuscode": 404, "isSuccess": false, "message": "LOGO not uploaded" });
  }
});

app.get("/fetchIAToken", jsonParser, function (req, res) {
  let response = payingagent.GetIAtoken(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})


app.post('/transferNFT', jsonParser, function (req, res) {
  let response = payingagent.transferNFT(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/approveNFTTransfer', jsonParser, function (req, res) {
  let response = payingagent.approveNFT(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/approveNFTTransferbywalletfile', jsonParser, function (req, res) {
  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });

        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/tempfolder/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

          let response = payingagent.approveNFT(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });
        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })
});

app.post('/publishToInvestors', jsonParser, function (req, res) {
  let response = payingagent.publishToInvestors(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});




app.get("/trustee/viewtableexp", jsonParser, function (req, res) {
  let response = IApayingagent.viewtable(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/trustee/uploadpdflogo', jsonParser, function (req, res) {

  fs.access("uploads", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(404).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      logoupload(req, res, async function (err) {
        if (err) {

          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/uploads/' + req.file.filename;
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::::" + ext);

          let response = IApayingagent.uploadpdflogo(req, res, uploadpath, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });
        }
        else {
          var output = { isSuccess: false, result: "Format not handled" };
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }
      })
    }
  });
});

app.get('/trustee/viewpdflogo', jsonParser, function (req, res) {
  let response = IApayingagent.viewpdflogo(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/savefornow', jsonParser, function (req, res) {
  let response = IApayingagent.savefornow(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/autosave', jsonParser, function (req, res) {
  let response = IApayingagent.savefornow(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.get('/trustee/recurring', jsonParser, function (req, res) {
  let response = IADealRecurring.viewtable(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

// app.post('/trustee/recurring', jsonParser, function (req, res) {
//   //res.send({ "isSuccess": true, "message": "Success" })

//   let response = IADealRecurring.viewtable(req, res, function (err, body) {
//       if (err)
//           res.send(err);
//       res.send(body);
//   });
// });

app.get('/trustee/bcstatus', jsonParser, function (req, res) {
  let response = IApayingagent.bcstatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/savedealservicerdate', jsonParser, function (req, res) {
  let response = IApayingagent.savedealservicerdate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/createupdate', jsonParser, function (req, res) {
  let response = IApayingagent.createupdate1(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.post('/trustee/viewaccounttable', jsonParser, function (req, res) {
  let response = IApayingagent.viewaccounttable(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/viewborrowingbasetable', jsonParser, function (req, res) {
  let response = IApayingagent.viewborrowingbasetable(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.post('/trustee/savetableexp', jsonParser, function (req, res) {
  let response = IApayingagent.savetableexp(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/edittableexp', jsonParser, function (req, res) {
  let response = IApayingagent.edittableexp(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/deletetableexp', jsonParser, function (req, res) {
  let response = IApayingagent.deletetableexp(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  })
});

app.post('/trustee/consolidatedaggregatesummarytodb', jsonParser, function (req, res) {
  let response = IAconsolidated.consolidatedaggregatesummarytodb(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/trustee/consolidatedaggregatesummarytobc', jsonParser, function (req, res) {
  let response = IAconsolidated.consolidatedaggregatesummarytobc(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

// app.post('/trustee/IADealcreation', jsonParser, function (req, res) {
//   let response = IAtrustee.Dealcreation(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });

//Fixed unit test case
//handled
app.get('/getDealsbyPayingagentId', jsonParser, function (req, res) {

  let response = dealOnbording.getPAbyid2(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

app.get('/trustee/dealservicerlist', jsonParser, function (req, res) {

  //   console.log(filePath)
  let response = trustee_route.dealservicerlist(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});
//api to save general details back to IM
app.post('/trustee/IAeditDealcreation', jsonParser, function (req, res) {
  let response = PAdeal.editDealcreation(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


app.post('/trustee/IAReportDetailsSave', jsonParser, function (req, res) {
  let response = PAdeal.SavePublishedReport(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

////Fixed unit test case
app.post('/trustee/getDealDetailsByPaymentDate', jsonParser, function (req, res) {

  let response = dealOnbording.getDealDetailsByPaymentDate(req, res, function (err, body) {
    if (err)
      res.send(err);
    winlog.info("in")
    res.send(body);
  });
});

app.post('/trustee/movefilestoIA', jsonParser, function (req, res) {
  let response = IAconsolidated.MovesummarydetailstoIA(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/createbatch', jsonParser, function (req, res) {
  let response = batch.CreateBatch(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.get('/getallbatchsbyVAId', jsonParser, function (req, res) {
  let response = batch.getallbatchbyVAId(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});

app.post('/updateBatchStatus', jsonParser, function (req, res) {

  let response = batch.updateBatchStatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//handled
app.post('/submitToUnderwriter', jsonParser, function (req, res) {

  let response = IPFSadd.Poolcreate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})
//internal purpose to update std loantape
app.post('/updatepreviewstdloantape', jsonParser, function (req, res) {
  let response = Preview.querymappingbyloanis(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//internal purpose to update std loantape
app.get('/getpreviewstdloantapebylatestdate', jsonParser, function (req, res) {
  let response = UA_pools.getbypooliAndAsOfDate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//internal use
app.post('/updateemailid', jsonParser, function (req, res) {


  let response = userSiginUp.updateuseremailid(req, res, function (err, body) {

    if (err)
      res.send(err);
    res.send(body);


  })

})

app.post('/dynamicFilter', jsonParser, function (req, res) {

  let response = UA_loans.DynamicFilters1(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

app.get('/getDistinctColumnValuesForFilters', jsonParser, function (req, res) {

  let response = UA_loans.getDistinctColumnValuesForFilters(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

//Fixed unit test case
app.get('/getloancolumndetails', jsonParser, function (req, res) {

  let response = UA_loans.getloancolumndetails(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})


app.post('/deleteAndAddLoansCpr', jsonParser, function (req, res) {
  let response = Preview.deleteAndAddLoans(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/updatepasswordwithhash', jsonParser, function (req, res) {
  let response = userSiginUp.updatewiithhahsh1(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/changestatus', jsonParser, function (req, res) {

  let response = IPFSadd.changestatus(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/setDowntime', jsonParser, function (req, res) {

  let response = downtimepopup.Updatedowntime(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})



app.post('/getDowntime', jsonParser, function (req, res) {

  let response = downtimepopup.getdowntime(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.post('/wholeLoanCommit', jsonParser, function (req, res) {
  let response1 = Wholeloaninvestment.WholeLoanCommit(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
});


// app.post('/wholeLoanInvest', jsonParser, function (req, res) {
//   let response1 = Wholeloaninvestment.WholeLoanInvest(req, res, function (err, body) {
//     if (err)
//       res.send(err);
//     res.send(body);
//   });
// });
//Mongoindex.createindex();

//internal purpose to update std loantape
app.get('/getpreviewstdloantapeusinglatestdate', jsonParser, function (req, res) {
  let response = UA_pools.getbypooliAndAsOfDateUsingPagination(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

//internal purpose to update std loantape
app.post('/LoantapeDynamicFilters', jsonParser, function (req, res) {
  let response = UA_pools.LoantapeDynamicFilters(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });
})

app.get('/getDistinctColumnValuesForFiltersByAsOfDate', jsonParser, function (req, res) {

  let response = UA_loans.getDistinctColumnValuesForFiltersByAsOfDate(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})


app.post('/generatePrivateAndPublickeyUsingPGP', jsonParser, function (req, res) {

  let response = PGPEncryptionAndKeyGeneration.generatePGPKeys(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})


app.post('/encryptZipFileUsingPgp', jsonParser, function (req, res) {

  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/tempfolder/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

          req.body.zipFilePath = uploadpath;
          let response = PGPEncryptionAndKeyGeneration.encryptZipWithPGP(req, res, function (err, body) {
            if (err)
              res.send(err);
            res.send(body);
          });

          // var output = { isSuccess: true, filename: req.file.filename, filetype: ext.toString(), result: "Document uploaded successfully!" };
          // res.send(output);

        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })
});


app.post('/addencryptedfileinSFTP', jsonParser, function (req, res) {

  console.log("in")
  fs.access("tempfolder", function (error) {
    if (error) {
      winlog.info("Directory Does Not exist!");
      return res.status(403).send({
        statuscode: 404,
        isSuccess: false,
        message: "Directory does not exist",
      });
    }
    else {
      tempfileupload(req, res, function (err) {
        if (err) {
          return res.status(404).json({ isSuccess: false, message: err.message, "statuscode": 404 });
        }
        winlog.info("__dirname::: " + __dirname);
        winlog.info(req.file);
        if (String(req.file) != "undefined") {

          var uploadpath = __dirname + '/tempfolder/' + req.file.filename;
          //filenamearr.push(uploadpath);
          winlog.info(uploadpath);

          var ext = path.extname(req.file.originalname);
          winlog.info("extension :::" + ext);

         
          mv(uploadpath, __dirname + '/uploads/uploads/' + req.body.template+"/"+req.file.filename, function (err) {
            if (err) { throw err; }
            winlog.info('file moved successfully');
          });
          
          var output = { isSuccess: true, filename: req.file.filename, filetype: ext.toString(), result: "Document uploaded successfully!" };
           res.send(output);

        } else {
          res.status(404).json({ isSuccess: false, message: "No file uploaded", "statuscode": 404 });
        }

      });
    }
  })
});

  
app.post('/decryptZipusingPgp', jsonParser, function (req, res) {

  let response = PGPEncryptionAndKeyGeneration.decryptPGP(req.body.encryptedFilePath,req.body.outputFilePath)

})

app.post('/logintovault', jsonParser, function (req, res) {
  let response = HashiCorpVault.vaultLogin(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})

app.get('/fetchsecret', jsonParser, function (req, res) {
  let response = HashiCorpVault.getdatafromvault(req, res, function (err, body) {
    if (err)
      res.send(err);
    res.send(body);
  });

})


var listen = http.createServer(app).listen(3005, () => winlog.info('Server started on port 3005'));
listen.setTimeout(2000000000);

