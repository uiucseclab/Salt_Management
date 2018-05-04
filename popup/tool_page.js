//const contentBox = document.querySelector("#content");


class Sha3 {

    /*
     * Keccak-f[b] permutations:
     *  - ℓ:  0  1   2   3   4   5    6
     *  - w:  1  2   4   8  16  32   64 (2ˡ)
     *  - b: 25 50 100 200 400 800 1600 (25 × 2ˡ)
     * SHA-3 specifies Keccak-f[1600] only, hence ℓ=6, w=64, b=1600.
     */


    /**
     * Generates 224-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash224(message, options) {
        return Sha3.keccak1600(1152, 448, message, options);
    }

    /**
     * Generates 256-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash256(message, options) {
        return Sha3.keccak1600(1088, 512, message, options);
    }

    /**
     * Generates 384-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash384(message, options) {
        return Sha3.keccak1600(832, 768, message, options);
    }

    /**
     * Generates 512-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash512(message, options) {
        return Sha3.keccak1600(576, 1024, message, options);
    }


    /**
     * Generates SHA-3 / Keccak hash of message M.
     *
     * @param   {number} r - Bitrate 'r' (b−c)
     * @param   {number} c - Capacity 'c' (b−r), md length × 2
     * @param   {string} M - Message
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     *
     * @private
     */
    static keccak1600(r, c, M, options) {
        const defaults = { padding: 'sha-3', msgFormat: 'string', outFormat: 'hex' };
        const opt = Object.assign(defaults, options);

        const l = c / 2; // message digest output length in bits

        let msg = null;
        switch (opt.msgFormat) {
            default: // convert string to UTF-8 to ensure all characters fit within single byte
            case 'string':    msg = utf8Encode(M);       break;
            case 'hex-bytes': msg = hexBytesToString(M); break; // mostly for NIST test vectors
        }

        /**
         * Keccak state is a 5 × 5 x w array of bits (w=64 for keccak-f[1600] / SHA-3).
         *
         * Here, it is implemented as a 5 × 5 array of Long. The first subscript (x) defines the
         * sheet, the second (y) defines the plane, together they define a lane. Slices, columns,
         * and individual bits are obtained by bit operations on the hi,lo components of the Long
         * representing the lane.
         */
        const state = [ [], [], [], [], [] ];
        for (let x=0; x<5; x++) {
            for (let y=0; y<5; y++) {
                state[x][y] = new Sha3.Long(0, 0);
            }
        }

        // append padding (for SHA-3 the domain is 01 hence M||0110*1) [FIPS §B.2]
        const q = (r/8) - msg.length % (r/8);
        if (q == 1) {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x81 : 0x86);
        } else {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x01 : 0x06);
            msg += String.fromCharCode(0x00).repeat(q-2);
            msg += String.fromCharCode(0x80);
        }

        // absorbing phase: work through input message in blocks of r bits (r/64 Longs, r/8 bytes)

        const w = 64; // for keccak-f[1600]
        const blocksize = r / w * 8; // block size in bytes (≡ utf-8 characters)

        for (let i=0; i<msg.length; i+=blocksize) {
            for (let j=0; j<r/w; j++) {
                const lo = (msg.charCodeAt(i+j*8+0)<< 0) + (msg.charCodeAt(i+j*8+1)<< 8)
                         + (msg.charCodeAt(i+j*8+2)<<16) + (msg.charCodeAt(i+j*8+3)<<24);
                const hi = (msg.charCodeAt(i+j*8+4)<< 0) + (msg.charCodeAt(i+j*8+5)<< 8)
                         + (msg.charCodeAt(i+j*8+6)<<16) + (msg.charCodeAt(i+j*8+7)<<24);
                const x = j % 5;
                const y = Math.floor(j / 5);
                state[x][y].lo = state[x][y].lo ^ lo;
                state[x][y].hi = state[x][y].hi ^ hi;
            }
            Sha3.keccak_f_1600(state);
        }

        // squeezing phase: first l bits of state are message digest

        // transpose state, concatenate (little-endian) hex values, & truncate to l bits
        let md = transpose(state).map(plane => plane.map(lane => lane.toString().match(/.{2}/g).reverse().join('')).join('')).join('').slice(0, l/4);

        // if required, group message digest into bytes or words
        if (opt.outFormat == 'hex-b') md = md.match(/.{2}/g).join(' ');
        if (opt.outFormat == 'hex-w') md = md.match(/.{8,16}/g).join(' ');

        return md;

        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

        function transpose(array) { // to iterate across y (columns) before x (rows)
            return array.map((row, r) => array.map(col => col[r]));
        }

        function utf8Encode(str) {
            try {
                return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
            } catch (e) { // no TextEncoder available?
                return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
            }
        }

        function hexBytesToString(hexStr) { // convert string of hex numbers to a string of chars (eg '616263' -> 'abc').
            const str = hexStr.replace(' ', ''); // allow space-separated groups
            return str=='' ? '' : str.match(/.{2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
        }
    }


    /**
     * Applies permutation Keccak-f[1600] to state a.
     *
     * @param {Long[][]} a - State to be permuted (5 × 5 array of Long).
     *
     * @private
     */
    static keccak_f_1600(a) {

        const nRounds = 24; // number of rounds nᵣ = 12 + 2ℓ, hence 24 for Keccak-f[1600] [Keccak §1.2]

        /**
         * Round constants: output of a maximum-length linear feedback shift register (LFSR) for the
         * ι step [Keccak §1.2, §2.3.5], keccak.noekeon.org/specs_summary.html.
         *
         *   RC[iᵣ][0][0][2ʲ−1] = rc[j+7iᵣ] for 0 ≤ j ≤ l
         * where
         *   rc[t] = ( xᵗ mod x⁸ + x⁶ + x⁵ + x⁴ + 1 ) mod x in GF(2)[x].
         */
        const RC = [
            '0000000000000001', '0000000000008082', '800000000000808a',
            '8000000080008000', '000000000000808b', '0000000080000001',
            '8000000080008081', '8000000000008009', '000000000000008a',
            '0000000000000088', '0000000080008009', '000000008000000a',
            '000000008000808b', '800000000000008b', '8000000000008089',
            '8000000000008003', '8000000000008002', '8000000000000080',
            '000000000000800a', '800000008000000a', '8000000080008081',
            '8000000000008080', '0000000080000001', '8000000080008008',
        ].map(c => Sha3.Long.fromString(c));


        // Keccak-f permutations
        for (let r=0; r<nRounds; r++) {
            // apply step mappings θ, ρ, π, χ, ι to the state 'a'

            // θ [Keccak §2.3.2]
            const C = [], D = []; // intermediate sub-states
            for (let x=0; x<5; x++) {
                C[x] = a[x][0].clone();
                for (let y=1; y<5; y++) {
                    C[x].hi = C[x].hi ^ a[x][y].hi;
                    C[x].lo = C[x].lo ^ a[x][y].lo;
                }
            }
            for (let x=0; x<5; x++) {
                // D[x] = C[x−1] ⊕ ROT(C[x+1], 1)
                const hi = C[(x+4)%5].hi ^ ROT(C[(x+1)%5], 1).hi;
                const lo = C[(x+4)%5].lo ^ ROT(C[(x+1)%5], 1).lo;
                D[x] = new Sha3.Long(hi, lo);
                // a[x,y] = a[x,y] ⊕ D[x]
                for (let y=0; y<5; y++) {
                    a[x][y].hi = a[x][y].hi ^ D[x].hi;
                    a[x][y].lo = a[x][y].lo ^ D[x].lo;
                }
            }

            // ρ + π [Keccak §2.3.4]
            let [ x, y ] = [ 1, 0 ];
            let current = a[x][y].clone();
            for (let t=0; t<24; t++) {
                const [ X, Y ] = [ y, (2*x + 3*y) % 5 ];
                const tmp = a[X][Y].clone();
                a[X][Y] = ROT(current, ((t+1)*(t+2)/2) % 64);
                current = tmp;
                [ x, y ] = [ X, Y ];
            }
            // note by folding the π step into the ρ step, it is only necessary to cache the current
            // lane; with π looping around x & y, it would be necessary to take a copy of the full
            // state for the A[X,Y] = a[x,y] operation

            // χ [Keccak §2.3.1]
            for (let y=0; y<5; y++) {
                const C = [];  // take a copy of the plane
                for (let x=0; x<5; x++) C[x] = a[x][y].clone();
                for (let x=0; x<5; x++) {
                    a[x][y].hi = (C[x].hi ^ ((~C[(x+1)%5].hi) & C[(x+2)%5].hi)) >>> 0;
                    a[x][y].lo = (C[x].lo ^ ((~C[(x+1)%5].lo) & C[(x+2)%5].lo)) >>> 0;
                }
            }

            // ι [Keccak §2.3.5]
            a[0][0].hi = (a[0][0].hi ^ RC[r].hi) >>> 0;
            a[0][0].lo = (a[0][0].lo ^ RC[r].lo) >>> 0;
        }

        function ROT(a, d) {
            return a.rotl(d);
        }

        function debugNist(s) { // debug of state s in NIST format
            const d = transpose(s).map(plane => plane.join('')).join('')
                .match(/.{2}/g).join(' ')
                .match(/.{23,48}/g).join('\n');
            console.log(d);
        }

        function debug5x5(s) { // debug of state s in 5×5 format 64-bit words
            const d = transpose(s).map(plane => plane.join(' ')).join('\n');
            console.log(d);
        }

        function transpose(array) { // to iterate across y (columns) before x (rows)
            return array.map((row, r) => array.map(col => col[r]));
        }
    }

}


/**
 * JavaScript has no support for 64-bit integers; this class provides methods required to support
 * 64-bit unsigned integers within Keccak.
 */
Sha3.Long = class {

    constructor(hi, lo) {
        this.hi = hi;
        this.lo = lo;
    }

    /**
     * Construct Long from string representation.
     */
    static fromString(str) {
        const [ hi, lo ] = str.match(/.{8}/g).map(i32 => parseInt(i32, 16));
        return new Sha3.Long(hi, lo);
    }

    /**
     * Copy 'this' Long.
     */
    clone() {
        return new Sha3.Long(this.hi, this.lo);
    }

    /**
     * Rotate left by n bits.
     */
    rotl(n) {
        if (n < 32) {
            const m = 32 - n;
            const lo = this.lo<<n | this.hi>>>m;
            const hi = this.hi<<n | this.lo>>>m;
            return new Sha3.Long(hi, lo);
        }
        if (n == 32) {
            return new Sha3.Long(this.lo, this.hi);
        }
        if (n > 32) {
            n -= 32;
            const m = 32 - n;
            const lo = this.hi<<n | this.lo>>>m;
            const hi = this.lo<<n | this.hi>>>m;
            return new Sha3.Long(hi, lo);
        }
    }

    /**
     * Representation of this Long as a hex string.
     */
    toString() {
        const hi = ('00000000'+this.hi.toString(16)).slice(-8);
        const lo = ('00000000'+this.lo.toString(16)).slice(-8);

        return hi + lo;
    }

};








function hexStringToUint8Array(hexString)
{
    if (hexString.length % 2 != 0)
        throw "Invalid hexString";
    var arrayBuffer = new Uint8Array(hexString.length / 2);

    for (var i = 0; i < hexString.length; i += 2) {
        var byteValue = parseInt(hexString.substr(i, 2), 16);
        if (byteValue == NaN)
            throw "Invalid hexString";
        arrayBuffer[i/2] = byteValue;
    }

    return arrayBuffer;
}

function bytesToASCIIString(bytes)
{
    return String.fromCharCode.apply(null, new Uint8Array(bytes));
}

function asciiToUint8Array(str)
{
    var chars = [];
    for (var i = 0; i < str.length; ++i)
        chars.push(str.charCodeAt(i));
    return new Uint8Array(chars);
}

function bytesToHexString(bytes)
{
    if (!bytes)
        return null;

    bytes = new Uint8Array(bytes);
    var hexBytes = [];

    for (var i = 0; i < bytes.length; ++i) {
        var byteString = bytes[i].toString(16);
        if (byteString.length < 2)
            byteString = "0" + byteString;
        hexBytes.push(byteString);
    }

    return hexBytes.join("");
}
////////////////////////////////////////////////////////////////////








const usernameInput = document.querySelector("#username");

function onError(e) {
    console.error(e);
}



document.addEventListener("DOMContentLoaded", function () {
    console.log(document.domain);//It outputs id of extension to console
    browser.tabs.query({ //This method output active URL 
        "active": true,
        "currentWindow": true,
        "status": "complete",
        "windowType": "normal"
    }, function (tabs) {
        for (tab in tabs) {
            console.log(tabs[tab].url);
            var url = new URL(tabs[tab].url);
            var domain = url.hostname;
            console.log(domain);
            
        }
    });
});

(function(proxied) {
    window.alert = function() {
        // do something here
        return proxied.apply(this, arguments);
    };
})(window.alert);

function makeid(length) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$";

    for (var i = 0; i < length; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}


function makeiv(length) {
    var text = "";
    var possible = "abcdef0123456789";

    for (var i = 0; i < length; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}








document.addEventListener("click", function(e) {
    let sha = new Sha3();
    if (!e.target.classList.contains("page-choice")) {
        return;
    }

    if (e.target.textContent == "New Password Salt") {
    
        browser.tabs.query({ //This method output active URL 
            "active": true,
            "currentWindow": true,
            "status": "complete",
            "windowType": "normal"
        }, function (tabs) {
            for (tab in tabs) {
                console.log(tabs[tab].url);
                var url = new URL(tabs[tab].url);
                var domain = url.hostname;
                console.log(domain);
                //console.log(makeid());
                
                var username = document.getElementsByName("input")[0].value;

                var token_IV = username+"IV"+domain;
                var token_key = username+"KEY"+domain;
                var token_salt = username+"salt"+domain;
                var IV = localStorage.getItem(Sha3.hash256(token_IV));
                if (username == null || username == ""|| username.length>30) {
                    var a = "Please enter a valid username.";
                    var b = "Please try again.";
                } else if (IV!="" && IV!= null){
                    if (confirm("Are you sure you want to replace the old password salt?(Only click yes if you are at password resetting page)")) {
                            var user1salt = makeid(8);
                            var a = "Hello  "+username;
                            var b = "This is your new password salt: "+user1salt;
/////////////////////////////encryption encrypt en_salt and generate IV and key here
                            window.crypto.subtle.generateKey(
                                {
                                    name: "AES-GCM",
                                    length: 256, 
                                },
                                true, 
                                ["encrypt", "decrypt"] 
                            ).then(function(key){
                                //returns a key object
                                console.log("testing generation");
                                console.log(key.type);
                                console.log(key.algorithm);
                                console.log(key.usages);
                                console.log(key.extractable);
                                window.crypto.subtle.exportKey(
                                    "raw", 
                                    key
                                )
                                .then(function(keydata){
                                    //returns the exported key data
                                    console.log("testing export");
                                    console.log(keydata);
                                    var dataView = new DataView(keydata);
                                    console.log("testing export 2");
                                    console.log(keydata.byteLength.toString());
                                    var expKey = "";
                                    for(var i=0; i<keydata.byteLength; i++) {
                                        // console.log(dataView.getUint8(i).toString(16));
                                        var temp = dataView.getUint8(i).toString(16);
                                        if(temp.length == 1)
                                            temp = "0" + temp;
                                        // console.log(temp);
                                        expKey = expKey + temp;
                                    }
                                    console.log(expKey);
                                    console.log("end export test");
                                    var c = "Key: " + expKey;
                                    localStorage.setItem(Sha3.hash256(token_key),expKey);
                                    console.log("Testing encrypt");
                            expKey = localStorage.getItem(Sha3.hash256(token_key));
                            var keyBuf = hexStringToUint8Array(expKey);
                            var IV = makeiv(64);
                            console.log("ivtext " + IV);
                            localStorage.setItem(Sha3.hash256(token_IV),IV);
                            var ivBuf = asciiToUint8Array(IV);
                            window.crypto.subtle.importKey(
                                "raw",
                                keyBuf,
                                "AES-GCM",
                                false, 
                                ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            ).then(function(key){
                                console.log("Import encrypt success@!");
                                    window.crypto.subtle.encrypt(
                                        {
                                            name: "AES-GCM",
                                            iv: ivBuf,
                                        },
                                        key,
                                        asciiToUint8Array(user1salt)
                                    ).then(function(encrypted_salted) {
                                        console.log("encryption with salt success!");
                                        // var msg_enc = String.fromCharCode.apply(null, new Uint16Array(encrypted));
                                        var msg_enc = new Uint8Array(encrypted_salted);
                                        var en_salt = bytesToHexString(msg_enc);
                                        console.log("encrypted: " + msg_enc);
                                        console.log("encrypted: " + en_salt);

                                        localStorage.setItem(Sha3.hash256(token_salt),en_salt+makeiv(16));
                                    }).catch(function(err) {
                                        console.error(err.toString());
                                    });
                                }).catch(function(err) {
                                    console.error(err.toString());
                                });

                                }).catch(function(err){
                                    
                                    console.error(err.toString());
                                });
                            }).catch(function(err){
                                console.log("dammit don't come here");
                                console.error(err);
                            });          
                            


                            //var IV = makeid(8);
                            //var key = makeid(8);
                            //var en_salt = user1salt;
/////////////////////////////encryption encrypt en_salt and generate IV and key here
                            
                            
                            //localStorage.setItem(Sha3.hash256(token_key),expKey);
                            
                            
                            //store it locally
                        } else {
///////////////////////////////decryption decrypt en_salt here
                            var IV = localStorage.getItem(Sha3.hash256(token_IV));
                            var expKey = localStorage.getItem(Sha3.hash256(token_key));
                            var en_salt = localStorage.getItem(Sha3.hash256(token_salt)).substring(0, 48);
                            var ivBuf = asciiToUint8Array(IV);
                            var keyBuf = hexStringToUint8Array(expKey);
//                            function displayStuff(username, salt, key, password_e, password_es, decrypted, decrypted_salt) {
                            window.crypto.subtle.importKey(
                                "raw",
                                keyBuf,
                                "AES-GCM",
                                false, 
                                ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            ).then(function(key){
                                console.log("decrypte import key success");
                                window.crypto.subtle.decrypt(
                                    {
                                        name: "AES-GCM",
                                        iv: ivBuf
                                    },
                                    key,
                                    hexStringToUint8Array(en_salt)
                                ).then(function (decrypted_salted) {
                                    console.log("decrypt salted success!");
                                    var decrypted_pass_salt = bytesToASCIIString(decrypted_salted);
                                    console.log("password: " + decrypted_pass_salt);
                                    var a = "Hello  "+username;
                                    var b = "This is your original password salt: "+decrypted_pass_salt;
                                    document.getElementById("username_show").textContent = a;
                                    document.getElementById("password_show").textContent = b;
                                }).catch(function(err) {
                                    console.error(err.toString());
                                });        
                            }).catch(function(err){
                                console.error(err.toString());
                            });
///////////////////////////////decryption decrypt en_salt here


                            
                        } 
                    
                }
                else {
                            var user1salt = makeid(8);
                            var a = "Hello  "+username;
                            var b = "This is your new password salt: "+user1salt;
/////////////////////////////encryption encrypt en_salt and generate IV and key here
                            window.crypto.subtle.generateKey(
                                {
                                    name: "AES-GCM",
                                    length: 256, 
                                },
                                true, 
                                ["encrypt", "decrypt"] 
                            ).then(function(key){
                                //returns a key object
                                console.log("testing generation");
                                console.log(key.type);
                                console.log(key.algorithm);
                                console.log(key.usages);
                                console.log(key.extractable);
                                window.crypto.subtle.exportKey(
                                    "raw", 
                                    key
                                )
                                .then(function(keydata){
                                    //returns the exported key data
                                    console.log("testing export");
                                    console.log(keydata);
                                    var dataView = new DataView(keydata);
                                    console.log("testing export 2");
                                    console.log(keydata.byteLength.toString());
                                    var expKey = "";
                                    for(var i=0; i<keydata.byteLength; i++) {
                                        // console.log(dataView.getUint8(i).toString(16));
                                        var temp = dataView.getUint8(i).toString(16);
                                        if(temp.length == 1)
                                            temp = "0" + temp;
                                        // console.log(temp);
                                        expKey = expKey + temp;
                                    }
                                    console.log(expKey);
                                    console.log("end export test");
                                    var c = "Key: " + expKey;
                                    localStorage.setItem(Sha3.hash256(token_key),expKey);
                                    console.log("Testing encrypt");
                            expKey = localStorage.getItem(Sha3.hash256(token_key));
                            var keyBuf = hexStringToUint8Array(expKey);
                            var IV = makeiv(64);
                            console.log("ivtext " + IV);
                            localStorage.setItem(Sha3.hash256(token_IV),IV);
                            var ivBuf = asciiToUint8Array(IV);
                            window.crypto.subtle.importKey(
                                "raw",
                                keyBuf,
                                "AES-GCM",
                                false, 
                                ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            ).then(function(key){
                                console.log("Import encrypt success@!");
                                    window.crypto.subtle.encrypt(
                                        {
                                            name: "AES-GCM",
                                            iv: ivBuf,
                                        },
                                        key,
                                        asciiToUint8Array(user1salt)
                                    ).then(function(encrypted_salted) {
                                        console.log("encryption with salt success!");
                                        // var msg_enc = String.fromCharCode.apply(null, new Uint16Array(encrypted));
                                        var msg_enc = new Uint8Array(encrypted_salted);
                                        var en_salt = bytesToHexString(msg_enc);
                                        console.log("encrypted: " + msg_enc);
                                        console.log("encrypted: " + en_salt);
                                        localStorage.setItem(Sha3.hash256(token_salt),en_salt+makeiv(16));
                                    }).catch(function(err) {
                                        console.error(err.toString());
                                    });
                                }).catch(function(err) {
                                    console.error(err.toString());
                                });

                                }).catch(function(err){
                                    
                                    console.error(err.toString());
                                });
                            }).catch(function(err){
                                console.log("dammit don't come here");
                                console.error(err);
                            });          
                            


                            //var IV = makeid(8);
                            //var key = makeid(8);
                            //var en_salt = user1salt;
/////////////////////////////encryption encrypt en_salt and generate IV and key here
                            
                            
                            //localStorage.setItem(Sha3.hash256(token_key),expKey);
                            
                            
                            //store it locally
                    //store it locally
                }

                

                document.getElementById("username_show").textContent = a;
                document.getElementById("password_show").textContent = b;
                


            }
        });
    }
      else if (e.target.textContent == "Delete Password Salt"){
        //retrieve password info from local

        browser.tabs.query({ //This method output active URL 
            "active": true,
            "currentWindow": true,
            "status": "complete",
            "windowType": "normal"
        }, function (tabs) {
            for (tab in tabs) {
                console.log(tabs[tab].url);
                var url = new URL(tabs[tab].url);
                var domain = url.hostname;
                console.log(domain);
                //console.log(makeid());
                var username = document.getElementsByName("input")[0].value;
                var token_IV = username+"IV"+domain;
                var token_key = username+"KEY"+domain;
                var token_salt = username+"salt"+domain;
                var IV = localStorage.getItem(Sha3.hash256(token_IV));
                if (username == null || username == "" || username.length>30) {
                    var c = "Please enter a valid username.";
                    var d = "Please try again.";
                } else if (IV == null || IV == ""){
                    
                    var c = "There is no password salt record for the current user.";
                    var d = "Please try again.";
                }
                else {
                    
                    if (confirm("Are you sure you want to delete the old password salt for this user at this domain?")) {

                            var c = "Hello  "+username;
                            var d = "You successfully deleted your old salt";

                            localStorage.removeItem(Sha3.hash256(token_IV),IV);
                            
                            localStorage.removeItem(Sha3.hash256(token_key),expKey);
                            
                            localStorage.removeItem(Sha3.hash256(token_salt),en_salt);
                        } else {
///////////////////////////////decryption decrypt en_salt here
                            var IV = localStorage.getItem(Sha3.hash256(token_IV));
                            var expKey = localStorage.getItem(Sha3.hash256(token_key));
                            var en_salt = localStorage.getItem(Sha3.hash256(token_salt)).substring(0, 48);
                            var ivBuf = asciiToUint8Array(IV);
                            var keyBuf = hexStringToUint8Array(expKey);
//                            function displayStuff(username, salt, key, password_e, password_es, decrypted, decrypted_salt) {
                            window.crypto.subtle.importKey(
                                "raw",
                                keyBuf,
                                "AES-GCM",
                                false, 
                                ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            ).then(function(key){
                                console.log("decrypte import key success");
                                window.crypto.subtle.decrypt(
                                    {
                                        name: "AES-GCM",
                                        iv: ivBuf
                                    },
                                    key,
                                    hexStringToUint8Array(en_salt)
                                ).then(function (decrypted_salted) {
                                    console.log("decrypt salted success!");
                                    var decrypted_pass_salt = bytesToASCIIString(decrypted_salted);
                                    console.log("password: " + decrypted_pass_salt);
                                    var c = "Hello  "+username;
                                    var d = "This is your current password salt: "+decrypted_pass_salt;
                                    document.getElementById("username_show").textContent = c;
                                    document.getElementById("password_show").textContent = d;
                                }).catch(function(err) {
                                    console.error(err.toString());
                                });        
                            }).catch(function(err){
                                console.error(err.toString());
                            });
///////////////////////////////decryption decrypt en_salt here

                            
                        } 
                }

                
                document.getElementById("username_show").textContent = c;
                document.getElementById("password_show").textContent = d;
            }
        })
    }

    else if (e.target.textContent == "Show Password Salt"){
        //retrieve password info from local

        browser.tabs.query({ //This method output active URL 
            "active": true,
            "currentWindow": true,
            "status": "complete",
            "windowType": "normal"
        }, function (tabs) {
            for (tab in tabs) {
                console.log(tabs[tab].url);
                var url = new URL(tabs[tab].url);
                var domain = url.hostname;
                console.log(domain);
                //console.log(makeid());
                var username = document.getElementsByName("input")[0].value;
                var token_IV = username+"IV"+domain;
                var token_key = username+"KEY"+domain;
                var token_salt = username+"salt"+domain;
                var IV = localStorage.getItem(Sha3.hash256(token_IV));
                if (username == null || username == "" || username.length>30) {
                    var pass1 = "Please enter a valid username.";
                }
                 else if (IV == null || IV == ""){
                    
                    var username = "There is no password salt record for the current user.";
                    var pass1 = "Please try again.";
                }

                else {
///////////////////////////////decryption decrypt en_salt here
                            var IV = localStorage.getItem(Sha3.hash256(token_IV));
                            var expKey = localStorage.getItem(Sha3.hash256(token_key));
                            var en_salt = localStorage.getItem(Sha3.hash256(token_salt)).substring(0, 48);
                            var ivBuf = asciiToUint8Array(IV);
                            var keyBuf = hexStringToUint8Array(expKey);
                            console.log("IV: " + IV);
                            console.log("ivBuf: " + ivBuf);
                            console.log("keyBuf: " + keyBuf);
                            console.log("en_salt: " + en_salt);
                            console.log("expKey: " + expKey);
                            console.log("arraysalt: " + hexStringToUint8Array(en_salt));
                            
                            window.crypto.subtle.importKey(
                                "raw",
                                keyBuf,
                                "AES-GCM",
                                false, 
                                ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            ).then(function(key){
                                console.log("decrypte import key success");
                                window.crypto.subtle.decrypt(
                                    {
                                        name: "AES-GCM",
                                        iv: ivBuf
                                    },
                                key,
                                hexStringToUint8Array(en_salt)
                                ).then(function (decrypted_salted) {
                                    console.log("decrypt salted success!");
                                    var decrypted_pass_salt = bytesToASCIIString(decrypted_salted);
                                    console.log("password: " + decrypted_pass_salt);
                                    var pass1 = decrypted_pass_salt;
                                    username ="User: "+username;
                                    if (pass1 == null||pass1 ==""){
                                        pass1 = "No salted password yet."
                                    }
                                    else {
                                        pass1 = "Salt: "+pass1;
                                    }
                                    document.getElementById("username_show").textContent = username;
                                    document.getElementById("password_show").textContent = pass1;
                                }).catch(function(err) {
                                    console.error(err.toString());
                                });        
                            }).catch(function(err){
                                console.error(err.toString());
                            });
///////////////////////////////decryption decrypt en_salt here
                    
                }

                
                document.getElementById("username_show").textContent = username;
                document.getElementById("password_show").textContent = pass1;
            }
        })
    }

    else {
    
        var chosenPage = "https://" + e.target.textContent;
        browser.tabs.create({
        url: chosenPage
    });
}
  
 
});

