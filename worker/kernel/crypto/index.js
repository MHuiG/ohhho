import kernel from "../../kernel"
const crypto = require('crypto');
/**
 * AES加密的配置 
 * 1.密钥 
 * 2.偏移向量 
 * 3.算法模式CBC 
 * 4.补全值
 */
var AES_conf = {
    key: getSecretKey(), //密钥
    iv: getSecretKey(), //偏移向量
}

/**
 * 读取密钥key
 */
function getSecretKey(){
    return AESKEY || "abcdabcdabcdabcd";
}

function getver(){
  return "OHH0000";
}
/**
 * AES_128_CBC 加密 
 * 128位 
 * return base64
 */
function EnCryptionAES(data) {
    let key = AES_conf.key;
    let iv = AES_conf.iv;
    let ver = getver();
    if(ver=="OHH0000"){
      return data
    }
    if(ver=="OHH0001"){
      iv = kernel.util.salt(16);
    }
    var cipherChunks = [];
    var cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    cipher.setAutoPadding(true);
    cipherChunks.push(cipher.update(data, 'utf8', 'base64'));
    cipherChunks.push(cipher.final('base64'));
    return ver+iv+cipherChunks.join('');
}

/**
 * 解密
 * return utf8
 */
function DeCryptionAES(data){
    let key = AES_conf.key;
    let iv = AES_conf.iv;
    if(data.substr(0,7)=="OHH0001"){
      iv = data.substr(7,16);
      data = data.substr(23,data.length-23);
    }else{
      return data
    }
    var cipherChunks = [];
    var decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(true);
    cipherChunks.push(decipher.update(data, 'base64', 'utf8'));
    cipherChunks.push(decipher.final('utf8'));
    return cipherChunks.join('');
}

export default {
  EnCryptionAES:EnCryptionAES,
  DeCryptionAES:DeCryptionAES
};
