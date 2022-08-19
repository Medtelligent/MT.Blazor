import CryptoJS from 'crypto-js'

export function encrypt(text, key) {
    return CryptoJS.AES.encrypt(text, key).toString();
}

export function decrypt(cipherText, key) {
    return CryptoJS.AES.decrypt(cipherText, key).toString(CryptoJS.enc.Utf8);
}