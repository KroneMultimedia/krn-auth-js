const KRNAuth = require('./KRNAuth');

// enter your partner-settings
var auth = new KRNAuth({
    'name': '',
    'crypt_key': '',
    'hmac_secret': ''
});

console.log(
    auth.validate(process.argv[2])
);

auth.deepValidate(process.argv[2])
    .then(token => console.log(token))
    .catch(error => console.log(error));

// use: node example.js <PASSPORT>
