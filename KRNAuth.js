const JWT = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');

// internal vs external use
const TRINITY_BASE_URL = process.env.KRN_HOST_PREFIX ? 'http://' + process.env.KRN_HOST_PREFIX + 'trinity.krn.krone.at' : 'https://trinity.krone.at';

class KRNAuth {
    ERR_INVALID_TOKEN = { error: 'Invalid Token' };

    constructor(partner) {
        this.partner = partner;
    }

    validate(token) {
        var self = this;

        if(!token.startsWith(this.partner.name)) {
            return self.ERR_INVALID_TOKEN;
        }

        // remove partner prefix
        var jwt = token.split(':')[1];

        // decode and validate token
        // https://www.npmjs.com/package/jsonwebtoken
        try {
            var decoded = JWT.verify(jwt, this.partner.hmac_secret, { algorithms: ['HS256'] });
        } catch(ex) {
            return self.ERR_INVALID_TOKEN;
        }

        // decrypt payload
        var payload = this.aesDecrypt(decoded.payload, this.partner.crypt_key);
        return JSON.parse(payload);
    }

    deepValidate(token) {
        var self = this;

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
                    reject(self.ERR_INVALID_TOKEN);
                }
            });
        });
    }

    aesDecrypt(ciphered, password) {
        var method = 'aes-256-cbc';
        var ivSize = 16;
        var data = this.hex2bin(ciphered);
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

    hex2bin (s) {
        const ret = []
        let i = 0
        let l
        s += ''
        for (l = s.length; i < l; i += 2) {
          const c = parseInt(s.substr(i, 1), 16)
          const k = parseInt(s.substr(i + 1, 1), 16)
          if (isNaN(c) || isNaN(k)) return false
          ret.push((c << 4) | k)
        }
        return String.fromCharCode.apply(String, ret)
    }
}

module.exports = KRNAuth;
