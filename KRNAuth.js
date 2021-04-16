const JWT = require('jsonwebtoken');
const fetch = require('node-fetch');

// internal vs external use
const TRINITY_BASE_URL = process.env.KRN_HOST_PREFIX ? 'http://' + process.env.KRN_HOST_PREFIX + 'trinity.krn.krone.at' : 'https://trinity.krone.at';

const ERR_INVALID_TOKEN = { error: 'Invalid Token' };

class KRNAuth {

    constructor(partner) {
        this.partner = partner;
    }

    validate(token) {
        if(!token.startsWith(this.partner.name)) {
            return ERR_INVALID_TOKEN;
        }

        // remove partner prefix
        var jwt = token.split(':')[1];

        // decode and validate token
        // https://www.npmjs.com/package/jsonwebtoken
        try {
            var decoded = JWT.verify(jwt, this.partner.hmac_secret, { algorithms: ['HS256'] });
        } catch(ex) {
            return ERR_INVALID_TOKEN;
        }

        // decrypt payload
        var payload = this.aesDecrypt(decoded.payload, this.partner.crypt_key);
        return JSON.parse(payload);
    }

    deepValidate(token) {
        var RENEW_QUERY = `
            mutation doRenew($passport: String!) {
                renew(passport: $passport) {
                    Message
                    Renewed
                    PassPort
                    Expires
                    Error
                    DecodedToken {
                        Email,
                        ID,
                        IntID,
                        NickName
                    }
                }
            }
        `;

        return new Promise(function (resolve, reject) {
            return fetch(TRINITY_BASE_URL + '/graphql', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    operationName: 'doRenew',
                    query: RENEW_QUERY,
                    variables: {
                        passport: token
                    }
                })
            })
            .then(response => response.json())
            .then((response) => {
                if (response.data !== null && response.errors == undefined) {
                    resolve(response.data.renew.DecodedToken);
                } else {
                    reject(ERR_INVALID_TOKEN);
                }
            });
        });
    }

    aesDecrypt(ciphered, password) {
        var method = 'aes-256-cbc';
        var ivSize = 16;
        var data = atob(ciphered);
        var ivData = data.substring(0, ivSize);
        var encData = data.substring(ivSize);

        var decipher = crypto.createDecipheriv(
            method,
            password,
            Buffer.from(ivData, "binary")
        );
        var output = decipher.update(encData, 'binary', 'utf8');
            output += decipher.final('utf8');
        return output;
    }
}

module.exports = KRNAuth;
