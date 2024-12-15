const { keccak256, toUtf8Bytes } = require("ethers");
const { v7: uuidv7 } = require('uuid');
var seedrandom = require('seedrandom');
require('dotenv').config();

const SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~";
const MAX_LENGTH = 500;

// convert string to hex
const stringToHex = (str) => {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        const hexValue = charCode.toString(16);
        hex += hexValue.padStart(2, '0');
    }
    return '0x' + hex;
}

// convert hex to string
const hexToString = (hex) => {
    hex = hex.slice(2); // remove 0x
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        const hexValue = hex.substr(i, 2);
        const decimalValue = parseInt(hexValue, 16);
        str += String.fromCharCode(decimalValue);
    }
    return str;
}

// add garbage
const addGarbage = (text) => {
    text = text + " ~~garbage: "
    let characters = keccak256(toUtf8Bytes(uuidv7())).slice(2); // get random characters and remove 0x
    while (text.length < MAX_LENGTH) {
        const character = characters[0];
        characters = characters.slice(1);
        text += character;
        if (characters.length == 0) {
            characters = keccak256(toUtf8Bytes(uuidv7())).slice(2);
        }
    }
    return text;
}

// encrypt
const encrypt = (text, secret) => {
    text = addGarbage(text);
    let result = '';
    for (let i = 0; i < text.length; i++) {
        const rng = seedrandom(keccak256(toUtf8Bytes(secret)) + i);
        result += String.fromCharCode(text.charCodeAt(i) ^ SYMBOLS.charCodeAt(Math.floor(rng() * 1000000) % SYMBOLS.length));
    }
    const shift = Math.floor((seedrandom(keccak256(toUtf8Bytes(secret)) + result.length))() * 1000000) % result.length;
    return stringToHex(result.slice(shift) + result.slice(0, shift));
}

// decrypt
const decrypt = (hex, secret) => {
    let str = hexToString(hex);
    const shift = str.length - Math.floor((seedrandom(keccak256(toUtf8Bytes(secret)) + str.length))() * 1000000) % str.length;
    str = str.slice(shift) + str.slice(0, shift);
    let result = '';
    for (let i = 0; i < str.length; i++) {
        var rng = seedrandom(keccak256(toUtf8Bytes(secret)) + i);
        result += String.fromCharCode(str.charCodeAt(i) ^ SYMBOLS.charCodeAt(Math.floor(rng() * 1000000) % SYMBOLS.length));
    }
    return result;
}

const secret = process.env.SECRET;
const text_to_encrypt = process.env.TEXT_TO_ENCRYPT;
console.log("Encrypted Text = ", encrypt(text_to_encrypt, secret));

const text_to_decrypt = process.env.TEXT_TO_DECRYPT;
console.log("Decrypted Text = ", decrypt(text_to_decrypt, secret));