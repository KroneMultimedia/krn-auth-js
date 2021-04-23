const KRNAuth = require('./KRNAuth');

// when installing via npm:
// const KRNAuth = require('krn-auth-js');

// enter your partner-settings
var auth = new KRNAuth({
    'name': '',
    'crypt_key': '',
    'hmac_secret': '',
    'rest_key': '',
    'rsa_key':  "", 
});

console.log(
    auth.validate(process.argv[2])
);

auth.deepValidate(process.argv[2])
    .then(token => console.log(token))
    .catch(error => console.log(error));

auth.sendRequest("GET", "/KRN/signing_test")
    .then((jso) => {
        console.log(jso);
    })
// use: node example.js <PASSPORT>
