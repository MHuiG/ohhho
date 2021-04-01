import kernel from "../../kernel"
const privatek = PRIVATEK
const privatepass = PRIVATEPASS
async function checkAccessToken(AT) {
  try{
    if(AT=="undefined"){
      return returnCode(7)
    }
    //true表示在有效期内AccessToken永久有效
    //false表示AccessToken在使用一次后就吊销
    //吊销机制是：AT与CapID联系，CapID与RefreshToken联系
    //checkAT将在第一次校验RT成功后将其吊销，参数实际上代表了是否校验RT吊销
    let checkRT =  false
    if(typeof CHECKRT != "undefined"){
      checkRT =  CHECKRT
    }
    const RefreshToken = JSON.parse(Decrypt(AT, privatek))
    let RToken = RefreshToken["RefreshToken"]
    const date = RefreshToken["date"]
    const now = (new Date()).valueOf()
    if (RefreshToken["privatepass"] == privatepass && now - 10 * 60000 < date && now + 10 * 60000 > date) {
        let banlist = await JSON.parse(await OHHHO.get("_banrt")) || []
        console.log(banlist)
        if((checktime(JSON.parse(Decrypt(RToken, privatek))) && await checkban(RToken)) || checkRT){
          if(!banlist.includes(RToken)){
            banlist.push(RToken)
            await OHHHO.put("_banrt", JSON.stringify(banlist), { expirationTtl: 5 * 60 })
          }
          return true
        }else{
          console.log("吊销的RT");
          return  returnCode(9)
        }
    } else { 
      console.log("过期的AT");
      return  returnCode(8)
    }
  }catch(e){
    return "!!CapError!!"+e
  }
}
async function CheckCaptcha(RToken,recapq,recapans) {
  let ans=await CheckRT(RToken)
  if(ans!=true){
    return ans
  }
  if (recapq && recapans) {
    try{
      const reqa = JSON.parse(Decrypt(recapq, privatek))
      if(await checkcap(reqa,recapans, RToken)){
        return true
      }else{
        return returnCode(5)
      }
    }catch(e){
      return returnCode(4)
    }
  }else{
    return returnCode(3)
  }
}
async function CheckRT(RToken) {
  try { 
    const _RT = JSON.parse(Decrypt(RToken, privatek))
    if (checktime(_RT)) {
      if(await checkban(RToken)){
        return true
      }else{
        return returnCode(2)
      }
    } else { 
      return returnCode(1) 
    }
  } catch (e) { 
    return returnCode(0)
  }
}
async function GetCapJson() {
  let json= (await fetch("https://raw.githubusercontent.com/MHuiG/Captcha-chemi/master/cap.json")).json()
  return json
}
async function checkcap(q,ans,RToken){
  let capi=await GetCapJson()
  capi=capi["0"]
  if(capi[q["capid"]][2] == ans&& RToken == q["RefreshToken"])
    return true
  return false
}

function returnCode(i) {
  const code = [
      "RefreshToken校验错误",
      "RefreshToken过期",
      "RefreshToken已失效",
      "Capthca需要校验",
      "Capthca校验错误",
      "Capthca答案错误",
      "CapthcaID丢失",
      "AccessToken校验失败",
      "AccessToken已过期",
      "AccessToken已吊销",
  ]
  const as = {
      capcode: i+1,
      msg: code[i] || "未知错误，请联系管理员"
  }
  const ans = JSON.stringify(as)
  return ans
}
function checktime(RT) {
  const date = RT["date"]
  const now = (new Date()).valueOf()
  if (now - 5*60000 < date && now + 5*60000 > date) { return true }
  return false
}
async function checkban(RT){
  const r = await JSON.parse(await OHHHO.get("_banrt"))
  let len=0
  if(r)
    len=r.length
  for(var i=0;i<len;i++){
    if(r[i]==RT){
      return false
    }
  }
  return true
}
function salt() {
  return kernel.util.salt(24)
}
function randomNum(minNum,maxNum){
  switch(arguments.length){
    case 1:
      return parseInt(Math.random()*minNum+1,10);
    case 2:
      return parseInt(Math.random()*(maxNum-minNum+1)+minNum,10);
    default:
      return 0;
  }
}
function Encrypt(str, pwd) {
  if (str == "") return "";
  str = escape(str);
  if (!pwd || pwd == "") { var pwd = "1234"; }
  pwd = escape(pwd);
  if (pwd == null || pwd.length <= 0) {
      console.log("Please enter a password with which to encrypt the message.");
      return null;
  }
  var prand = "";
  for (var I = 0; I < pwd.length; I++) {
      prand += pwd.charCodeAt(I).toString();
  }
  var sPos = Math.floor(prand.length / 5);
  var mult = parseInt(prand.charAt(sPos) + prand.charAt(sPos * 2) + prand.charAt(sPos * 3) + prand.charAt(sPos * 4) + prand.charAt(sPos * 5));

  var incr = Math.ceil(pwd.length / 2);
  var modu = Math.pow(2, 31) - 1;
  if (mult < 2) {
      console.log("Algorithm cannot find a suitable hash. Please choose a different password. \nPossible considerations are to choose a more complex or longer password.");
      return null;
  }
  var salt = Math.round(Math.random() * 1000000000) % 100000000;
  prand += salt;
  while (prand.length > 10) {
      prand = (parseInt(prand.substring(0, 10)) + parseInt(prand.substring(10, prand.length))).toString();
  }
  prand = (mult * prand + incr) % modu;
  var enc_chr = "";
  var enc_str = "";
  for (var I = 0; I < str.length; I++) {
      enc_chr = parseInt(str.charCodeAt(I) ^ Math.floor((prand / modu) * 255));
      if (enc_chr < 16) {
          enc_str += "0" + enc_chr.toString(16);
      } else
          enc_str += enc_chr.toString(16);
      prand = (mult * prand + incr) % modu;
  }
  salt = salt.toString(16);
  while (salt.length < 8) salt = "0" + salt;
  enc_str += salt;
  return enc_str;
}

function Decrypt(str, pwd) {
  if (str == "") return "";
  if (!pwd || pwd == "") { var pwd = "1234"; }
  pwd = escape(pwd);
  if (str == null || str.length < 8) {
      console.log("A salt value could not be extracted from the encrypted message because it's length is too short. The message cannot be decrypted.");
      return;
  }
  if (pwd == null || pwd.length <= 0) {
      console.log("Please enter a password with which to decrypt the message.");
      return;
  }
  var prand = "";
  for (var I = 0; I < pwd.length; I++) {
      prand += pwd.charCodeAt(I).toString();
  }
  var sPos = Math.floor(prand.length / 5);
  var mult = parseInt(prand.charAt(sPos) + prand.charAt(sPos * 2) + prand.charAt(sPos * 3) + prand.charAt(sPos * 4) + prand.charAt(sPos * 5));
  var incr = Math.round(pwd.length / 2);
  var modu = Math.pow(2, 31) - 1;
  var salt = parseInt(str.substring(str.length - 8, str.length), 16);
  str = str.substring(0, str.length - 8);
  prand += salt;
  while (prand.length > 10) {
      prand = (parseInt(prand.substring(0, 10)) + parseInt(prand.substring(10, prand.length))).toString();
  }
  prand = (mult * prand + incr) % modu;
  var enc_chr = "";
  var enc_str = "";
  for (var I = 0; I < str.length; I += 2) {
      enc_chr = parseInt(parseInt(str.substring(I, I + 2), 16) ^ Math.floor((prand / modu) * 255));
      enc_str += String.fromCharCode(enc_chr);
      prand = (mult * prand + incr) % modu;
  }
  return unescape(enc_str);
}
let captcha={
  checkAccessToken:checkAccessToken,
  getRefreshToken: function(){
    const _RT = {
      date: (new Date()).valueOf(),
      salt: salt()
    }
    const RT = Encrypt(JSON.stringify(_RT), privatek)
    return RT
  },
  getAccessToken: async function(RToken,recapq,recapans){
    let ans=await CheckCaptcha(RToken,recapq,recapans)
    if(ans!=true){
      return ans
    }
    const _AccessToken = {
        date: (new Date()).valueOf(),
        salt: salt(),
        RefreshToken: RToken,
        privatepass: privatepass
    }
    const AT = Encrypt(JSON.stringify(_AccessToken), privatek)
    return AT
  },
  getCap:async function(RToken){
    let ans=await CheckRT(RToken)
    if(ans!=true){
      return ans
    }
    let capi=await GetCapJson()
    capi=capi["0"]
    // const id = randomNum(0,10185)
    const id = 0  //test
    let _CAP = {
      RefreshToken: RToken,
      capque : capi[id][1],
      capans : capi[id][2],
      capid : id,
      salt:salt()
    }
    const recapq = Encrypt(JSON.stringify(_CAP), privatek)
    return recapq
  },
  getCapImg:async function(RToken,recapq){
    let ans=await CheckRT(RToken)
    if(ans!=true){
      return ans
    }
    if(recapq){
      try { 
        const _CAP =JSON.parse(Decrypt(recapq, privatek))
        return fetch(`https://raw.githubusercontent.com/MHuiG/Captcha-chemi/master/img/${_CAP["capque"]}.gif`)
      } catch (e) { 
        return returnCode(4) 
      }
    }else{
      return returnCode(6)
    }
  }
}
export default captcha
