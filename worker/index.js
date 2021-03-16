import md from "marked";
import xss from 'xss'
const md5 = require('blueimp-md5')
const uaparser = require('ua-parser-js')
const highligher = require('highlight.js')
const crypto = require('crypto');

md.setOptions({
  gfm: true,
  tables: true,
  breaks: true,
  pedantic: false,
  sanitize: false,
  smartLists: true,
  smartypants: true,
  highlight(code) {
    return highligher.highlightAuto(code).value;
  },
});

function XSS (o) {
  return xss(o, {
    onIgnoreTagAttr (tag, name, value, isWhiteAttr) {
      if (name === 'class') {
        return `${name}="${xss.escapeAttrValue(value)}"`
      }
    },
    onTag (tag, html, options) {
      if (tag === 'input' && (html.match(/<input disabled="" type="checkbox">/) || html.match(/<input checked="" disabled="" type="checkbox">/))) {
        return html
      }
    }
  })
}

async function handleRequest(request) {
  const req = request;
  const urlStr = req.url;
  const urlObj = new URL(urlStr);
  const path = urlObj.href.substr(urlObj.origin.length);
  const headers_init = {
    headers: {
      "content-type": "application/javascript; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  };
  const CFConnectingIP=request.headers.get("CF-Connecting-IP")
  const XForwardedFor=request.headers.get("X-Forwarded-For")
  const CfIpcountry=request.headers.get("Cf-Ipcountry")
  const XRealIP=new Map(request.headers).get('x-real-ip')
  const privatek = PRIVATEK
  const privatepass = PRIVATEPASS
  /************************************** */
  // 安全检查
  let analytics=await GETAnalytics()
  let result=(await analytics.json()).result
  if(result.totals.requests>30000){
    await SecurityLevel("under_attack")
    await Schedules("0 0 * * *")
  }
  if(result.totals.requests>35000){
    let routes=await GETRoutes()
    let routesresult=(await routes.json()).result
    let routeid=0
    for (let index = 0; index < routesresult.length; index++) {
      const element = routesresult[index];
      if(element.script==WORKERNAME){
        routeid=element.id
        break
      }
    }
    if(routeid){
      await DeleteRouteById(routeid)
    }
  }

  /************************************** */
  try {
    if (path == "/favicon.ico") {
      return fetch("https://cdn.jsdelivr.net/npm/mhg@latest");
    }
    if (path.startsWith("/md")) {
      if(request.method=="POST"){
        const formData = await request.formData()
        const body = {}
        for (const entry of formData.entries()) {
          body[entry[0]] = entry[1]
        }
        const s = body.s
        return new Response(md(XSS(s)), headers_init)
      }
    }
    if (path.startsWith("/comment")) {
      if(request.method=="POST"){
        let body=await GetPostBody(request)
        body.ip = CFConnectingIP || XRealIP
        body.XForwardedFor = XForwardedFor
        body.CfIpcountry = CfIpcountry
        /************************************** */
        // 检测 request  IP-Time
        // 15min
        const now = new Date()
        let p={}
        p.ip=body.ip
        p.XForwardedFor=body.XForwardedFor
        p.CfIpcountry=body.CfIpcountry
        p.time=new Date()
        let q=[]
        let IPTime=await OHHHO.get("IPTime")
        if(IPTime){
          q=JSON.parse(IPTime)
        }
        let num=0
        for (const it of q) {
         let minutes=GetTimeMinutes(p.time,new Date(it.time))
         if(minutes>15){
           // 移除过时数据
          var index = q.indexOf(it)
          if (index > -1) {
            q.splice(index, 1);
          }
         }else{
           if ((p.ip&&p.ip==it.ip)||(p.XForwardedFor&&p.XForwardedFor==it.XForwardedFor)) {
             num++
           }
         }
        }
        if(num>15){
          // Cloudflare API 防火墙规则
          // https://api.cloudflare.com/#firewall-rules-properties
          // https://developers.cloudflare.com/firewall/api
          // https://developers.cloudflare.com/firewall/cf-firewall-rules

          let filters = await GETFilters()
          let result=(await filters.json()).result
          let flag=0
          let i=0
          for(;i<result.length;i++){
            if(result[i].ref&&result[i].ref=="OHHHO"){
              flag=1
              break
            }
          }
          if(flag){
            let item=result[i]
            let expression = item.expression
            if (p.ip) {
              expression += " or (ip.src eq "+p.ip+")"
            }
            if (p.XForwardedFor) {
              expression += " or (http.x_forwarded_for eq "+p.XForwardedFor+")"
            }
            item.expression=expression
            await fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/filters", {
              method: "PUT",
              headers: {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
                "X-Auth-Email": AUTHEMAIL,
                "X-Auth-Key": AUTHKEY,
                "Content-Type": "application/json",
              },
              body: JSON.stringify([item])
            }));
          }else{
            let expression = "(ip.src eq 127.0.0.1)"
            if (p.ip) {
              expression = "(ip.src eq "+p.ip+")"
            } else if (p.XForwardedFor) {
              expression = "(http.x_forwarded_for eq "+p.XForwardedFor+")"
            }
            await fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/firewall/rules", {
              method: "POST",
              headers: {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
                "X-Auth-Email": AUTHEMAIL,
                "X-Auth-Key": AUTHKEY,
                "Content-Type": "application/json",
              },
              body: '[{"description": "OHHHO","action": "block","filter": {"expression": "'+expression+'","ref": "OHHHO"}}]'
            }));
          }
          return new Response("本站正遭受攻击，请稍后再试！", headers_init);
        }
        if(q.length>=10){
          if(typeof CAPTCHAAPI != "undefined"){
            let sc=await fetch(new Request(CAPTCHAAPI+"/CheckChallengeCaptcha?accesstoken="+body.accesstoken, {
              method: "GET",
              headers: {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
              },
            }));
            sc=await sc.text()
            if(sc!="OK"){
              return new Response(sc, headers_init);
            }
        }else{
          let ans=await checkAT(body.accesstoken,privatek,privatepass)
          if(ans!=true){
            return ans
          }
        }
        }
        if(q.length>=12){
          let wait_attack=await OHHHO.get("ohhho_attack")
          if(wait_attack){
            wait_attack=JSON.parse(wait_attack)
            var minutes=GetTimeMinutes(new Date(),new Date(wait_attack.time))
            if(minutes>1){
              await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
            }else{
              return new Response("系统触发了防御机制-强制等待策略，请一分钟后重试！", headers_init);
            }
          }else{
            await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
          }
        }
        if(q.length>20){
          await SecurityLevel("under_attack")
          await Schedules("0 0 * * *")
          return new Response("本站正遭受攻击，请稍后再试！！", headers_init);
        }



        q.push(p)
        await OHHHO.put("IPTime",JSON.stringify(q))

        // 检测大文本攻击
        var la =body.comment?body.comment.length:0
        var lb =body.link?body.link.length:0
        var lc =body.nick?body.nick.length:0
        var ln = Math.max( la,lb,lc )
        if(ln>1000000){
          return new Response("那太大了", headers_init);
        }
        /************************************** */

        let Item = toItem(body)
        let ls=[]
        let c=0
        if(typeof IPFSAPI != "undefined"){
          let hash= await OHHHO.get("IPFS-"+Item.url) // KV / IPFS
          if(hash){
            c=await IPFSCat(hash)
            c=await c.text()
            c=DeCryptionAES(c)
          }
        }else{
          c= await OHHHO.get(Item.url) // KV Only
          if(c){
            c=DeCryptionAES(c)
          }
        }
        if(c){
          ls=JSON.parse(c)
          if(Item.rid){
            let children=[]
            let index = 0
            let element
            for (; index < ls.length; index++) {
              element = ls[index];
              if(element.id==Item.pid){
                if(element.children){
                  children=element.children
                }
                children.push(Item)
                element.children=children
                ls[index]=element
                break;
              }
            }
          }else{
            ls.push(Item)
          }
        }else{
          ls.push(Item)
        }
        if(typeof IPFSAPI != "undefined"){
          let sc= await IPFSAdd(EnCryptionAES(JSON.stringify(ls)))
          sc=await sc.json()
          await OHHHO.put("IPFS-"+Item.url,sc.Hash) // KV / IPFS
        }else{
          await OHHHO.put(Item.url,EnCryptionAES(JSON.stringify(ls))) // KV Only
        }
        try{
          if(typeof APIPATH != "undefined"){
            await fetch(new Request(APIPATH, {
              method: "POST",
              headers: {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
              },
              body: JSON.stringify(Item)
            }));
          }
        }catch(e){}
        const meta = await OHHHO.get("meta")
        let lm=[]
        if(meta){
          lm=JSON.parse(meta)
          var index = lm.indexOf(Item.url)
          if (index == -1) {
            lm.push(Item.url)
          }
        }else{
          lm.push(Item.url)
        }
        await OHHHO.put("meta",JSON.stringify(lm))
        let it = getIt(Item)
        return new Response(JSON.stringify(it), headers_init)
      }else if(request.method=="GET"){
        const type = urlObj.searchParams.get('type')
        const path = urlObj.searchParams.get('path')
        let c=0
        if(typeof IPFSAPI != "undefined"){
          let hash= await OHHHO.get("IPFS-"+path) // KV / IPFS
          if(hash){
            c=await IPFSCat(hash)
            c=await c.text()
            c=DeCryptionAES(c)
          }
        }else{
          c= await OHHHO.get(path) // KV Only
          if(c){
            c=DeCryptionAES(c)
          }
        }
        if(type=="count"){
          let num=0
          if(c){
            let ls=JSON.parse(c)
            num=ls.length
          }
          return new Response(JSON.stringify(num), headers_init)
        }else if(type=="totalPages"){
          const pageSize = urlObj.searchParams.get('pageSize')
          let num=0
          if(c){
            let ls=JSON.parse(c)
            num = Math.ceil(ls.length / pageSize)
          }
          return new Response(JSON.stringify(num), headers_init)
        }else{
          const pageSize = urlObj.searchParams.get('pageSize')
          const page = urlObj.searchParams.get('page')
          if(c){
            let ls=JSON.parse(c)
            let num=ls.length
            let p=[]
            for (let i = 0; i < num; i++) {
              let ele = getIt(ls[i]);
              if(ele.approval){
                p.push(ele)
              }
            }
            p.reverse()
            let q=[]
            for (let index =(page-1)*pageSize; (index < page*pageSize)&&(index<p.length) ; index++) {
              const element = p[index];
              q.push(element)
            }
            return new Response(JSON.stringify(q), headers_init)
          }
          return new Response(JSON.stringify({}), headers_init)
        }
      }
    }
    /*********************************************************************************************** */
    // Captcha
    if (path.startsWith("/getrefreshtoken")) {
      const _RT = {
          date: (new Date()).valueOf(),
          salt: salt()
      }
      const RT = Encrypt(await JSON.stringify(_RT), privatek)
      return new Response(RT, headers_init)
    }
    if (path.startsWith("/getaccesstoken")) {
      const RToken = urlObj.searchParams.get('refreshtoken')
      let recapq=urlObj.searchParams.get('recapq')
      let recapans=urlObj.searchParams.get('recapans')
      let ans=await CheckCaptcha(RToken,privatek,recapq,recapans)
      if(ans!=true){
        return ans
      }
      const _AccessToken = {
          date: (new Date()).valueOf(),
          salt: salt(),
          RefreshToken: RToken,
          privatepass: privatepass
      }
      const AT = Encrypt(await JSON.stringify(_AccessToken), privatek)
      return new Response(AT, headers_init)
  }
    if (path.startsWith("/getcap")) {
      let RToken=urlObj.searchParams.get('refreshtoken')
      let ans=await CheckRT(RToken,privatek)
      if(ans!=true){
        return ans
      }
      let capi=await GetCapJson()
      capi=capi["0"]
      const id = randomNum(0,10185)
      // const id = 0  //test
      let _CAP = {
        RefreshToken: RToken,
        capque : capi[id][1],
        capans : capi[id][2],
        capid : id,
        salt:salt()
      }
      const recapq = Encrypt(await JSON.stringify(_CAP), privatek)
      return new Response(recapq, headers_init)
    }
    if (path.startsWith("/getimgcap")) {
      let ans=await CheckRT(urlObj.searchParams.get('refreshtoken'),privatek)
      if(ans!=true){
        return ans
      }
      if(urlObj.searchParams.get('recapq')){
          try { 
            await JSON.parse(Decrypt(urlObj.searchParams.get('recapq'), privatek)) 
          } catch (e) { 
            return returnc(4) 
          }
          const _CAP = await JSON.parse(Decrypt(urlObj.searchParams.get('recapq'), privatek))
          return fetch(`https://raw.githubusercontent.com/MHuiG/Captcha-chemi/master/img/${_CAP["capque"]}.gif`)
      }else{
        return returnc(6)
      }
    }
    if (path.startsWith("/ChallengeCaptcha")) {
      if(typeof CAPTCHAAPI != "undefined"){
          let sc=await fetch(new Request(CAPTCHAAPI+"/ChallengeCaptchaScript", {
            method: "GET",
            headers: {
              "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
            },
          }));
          sc=await sc.text()
          return new Response(sc, headers_init);
      }
      return new Response(ScriptChallenge, headers_init);
    }
    /*********************************************************************************************** */
    // IPFS
    if (path.startsWith("/ipfsadd")) {
      let s= urlObj.searchParams.get('s')||"Hello World!"
      let sc= await IPFSAdd(s)
      sc=await sc.text()
      return new Response(sc, headers_init);
    }
    if (path.startsWith("/ipfs")) {
      const url = new URL(request.url)
      url.hostname = "cloudflare-ipfs.com"
      return await fetch(url.toString(), request)
    }
    /*********************************************************************************************** */
    return new Response("Hello world", headers_init);
  } catch (e) {
    console.log(e);
    return new Response("!!Error!!"+e, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
}

var NewID = function() {
  var str = "abcdefghijklmnopqrstuvwxyz0123456789";
  var result = "";
  for(var i = 0; i < 24; i++) {
      result += str[parseInt(Math.random() * str.length)];
  }
  return result;
}

var toItem = function(body){
  let Item={}
  Item.approval=true // 批准状态
  Item.comment=body.comment
  Item.commentHtml=md(XSS(body.comment))
  Item.createdAt=new Date()
  Item.mail=body.mail
  Item.mailMd5=md5(body.mail)
  Item.ua=body.ua
  const ua=uaparser(Item.ua)
  Item.browser=ua.browser
  Item.os=ua.os
  Item.ip=body.ip
  Item.id=NewID()
  Item.link=XSS(body.link)
  Item.nick=XSS(body.nick)
  Item.url=body.url
  if(body.rid){
    Item.rid=body.rid
  }
  if(body.pid){
    Item.pid=body.pid
  }
  return Item
}
var getIt = function(Item){
  let it={}
  it.approval=Item.approval
  it.comment=Item.commentHtml
  it.mailMd5=Item.mailMd5
  it.createdAt=Item.createdAt
  it.id=Item.id
  it.nick=Item.nick
  it.link=Item.link
  it.url=Item.url
  if(Item.rid){
    it.rid=Item.rid
  }
  if(Item.pid){
    it.pid=Item.pid
  }
  if(Item.children){
    let p=[]
    for (let index = 0; index < Item.children.length; index++) {
      const element = getIt(Item.children[index]);
      p.push(element)
    }
    it.children=p
  }
  return it
}
/*********************************************************************************************** */
// Captcha
async function checkAT(AT,privatek,privatepass) {
  try{
    if(AT=="undefined"){
      return returnc(7)
    }
    //true表示在有效期内AccessToken永久有效
    //false表示AccessToken在使用一次后就吊销
    //吊销机制是：AT与CapID联系，CapID与RefreshToken联系
    //checkAT将在第一次校验RT成功后将其吊销，参数实际上代表了是否校验RT吊销
    let checkRT =  false
    if(typeof CHECKRT != "undefined"){
      checkRT =  CHECKRT
    }
    const RefreshToken = await JSON.parse(Decrypt(AT, privatek))
    let RToken = RefreshToken["RefreshToken"]
    const date = RefreshToken["date"]
    const now = (new Date()).valueOf()
    if (RefreshToken["privatepass"] == privatepass && now - 10 * 60000 < date && now + 10 * 60000 > date) {
        let banlist = await JSON.parse(await OHHHO.get("_banrt")) || []
        console.log(banlist)
        if((checktime(await JSON.parse(Decrypt(RToken, privatek))) && await checkban(RToken)) || checkRT){
          if(!banlist.includes(RToken)){
            banlist.push(RToken)
            await OHHHO.put("_banrt", await JSON.stringify(banlist), { expirationTtl: 5 * 60 })
            }
          return true
        }else{
          console.log("吊销的RT");
          return  returnc(9)
        }
        
    } else { 
      console.log("过期的AT");
      return  returnc(8)
    }
  }catch(e){
    return new Response("!!CapError!!"+e, { headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" } })
  }
}
async function CheckCaptcha(RToken,privatek,recapq,recapans) {
  let ans=await CheckRT(RToken,privatek)
  if(ans!=true){
    return ans
  }
  if (recapq && recapans) {
    try{
      await JSON.parse(Decrypt(recapq, privatek))
    }catch(e){
      return returnc(4)
    }
    const reqa = await JSON.parse(Decrypt(recapq, privatek))
    if(await checkcap(reqa,recapans, RToken)){
        return true
    }else{
      return returnc(5)
    }
  }else{
      return returnc(3)
  }
}
async function CheckRT(RToken,privatek) {
  try { 
    await JSON.parse(Decrypt(RToken, privatek))
  } catch (e) { 
    return returnc(0)
  }
  const _RT = await JSON.parse(Decrypt(RToken, privatek))
  if (checktime(_RT)) {
    if(await checkban(RToken, privatek)){
      return true
    }else{
      return returnc(2)
    }
  } else { 
    return returnc(1) 
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

function returnc(i) {
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
  return new Response(ans, { headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" } })
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
  var str = "abcdefghijklmnopqrstuvwxyz0123456789";
  var result = "";
  for (var i = 0; i < 24; i++) {
      result += str[parseInt(Math.random() * str.length)];
  }
  return result;
}
function randomNum(minNum,maxNum){
  switch(arguments.length){
      case 1:
          return parseInt(Math.random()*minNum+1,10);
      break;
      case 2:
          return parseInt(Math.random()*(maxNum-minNum+1)+minNum,10);
      break;
          default:
              return 0;
          break;
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
const ScriptChallenge=`
var script = document.createElement('style')
script.innerText=\`
.captcha {
  color: var(--ohhho-mark-text);
  border: 1px solid #c5c5c5;
  width: 198px;
  margin: 0 auto;
  height: 50px;
  padding-top: 15px;
  border-radius: 7px;
}
@supports (-webkit-appearance: none) or (-moz-appearance: none) {
  .captcha input[type="checkbox"] {
    --active: #275efe;
    --active-inner: #fff;
    --focus: 2px rgba(39, 94, 254, 0.3);
    --border: #bbc1e1;
    --border-hover: #275efe;
    --background: #fff;
    --disabled: #f6f8ff;
    --disabled-inner: #e1e6f9;
    -webkit-appearance: none;
    -moz-appearance: none;
    height: 21px;
    outline: none;
    display: inline-block;
    vertical-align: top;
    position: relative;
    margin: 0;
    cursor: pointer;
    border: 1px solid var(--bc, var(--border));
    background: var(--b, var(--background));
    -webkit-transition: background 0.3s, border-color 0.3s, box-shadow 0.2s;
    transition: background 0.3s, border-color 0.3s, box-shadow 0.2s;
  }
  .captcha input[type="checkbox"]:after {
    content: "";
    display: block;
    left: 0;
    top: 0;
    position: absolute;
    -webkit-transition: opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
    transition: opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
    transition: transform var(--d-t, 0.3s) var(--d-t-e, ease),
      opacity var(--d-o, 0.2s);
    transition: transform var(--d-t, 0.3s) var(--d-t-e, ease),
      opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
  }
  .captcha input[type="checkbox"]:checked {
    --b: var(--active);
    --bc: var(--active);
    --d-o: 0.3s;
    --d-t: 0.6s;
    --d-t-e: cubic-bezier(0.2, 0.85, 0.32, 1.2);
  }
  .captcha input[type="checkbox"]:disabled,
  .captcha input[type="checkbox"]:disabled:checked {
    --b: var(--disabled-inner);
    --bc: var(--border);
  }
  .captcha input[type="checkbox"]:disabled + label {
    cursor: not-allowed;
  }
  .captcha input[type="checkbox"]:hover:not(:checked):not(:disabled) {
    --bc: var(--border-hover);
  }
  .captcha input[type="checkbox"]:focus,
  .captcha input[type="radio"]:focus {
    box-shadow: 0 0 0 var(--focus);
  }
  .captcha input[type="checkbox"]:not(.switch),
  .captcha input[type="radio"]:not(.switch) {
    width: 21px;
  }
  .captcha input[type="checkbox"]:not(.switch):after,
  .captcha input[type="radio"]:not(.switch):after {
    opacity: var(--o, 0);
  }
  .captcha input[type="checkbox"]:not(.switch):checked {
    --o: 1;
  }
  .captcha input[type="checkbox"] + label {
    font-size: 14px;
    line-height: 21px;
    display: inline-block;
    vertical-align: top;
    cursor: pointer;
    margin-left: 4px;
  }

  .captcha input[type="checkbox"]:not(.switch) {
    border-radius: 7px;
  }
  .captcha input[type="checkbox"]:not(.switch):after {
    width: 5px;
    height: 9px;
    border: 2px solid var(--active-inner);
    border-top: 0;
    border-left: 0;
    left: 7px;
    top: 4px;
    -webkit-transform: rotate(var(--r, 20deg));
    transform: rotate(var(--r, 20deg));
  }
  .captcha input[type="checkbox"]:not(.switch):checked {
    --r: 43deg;
  }
  .captcha input[type="checkbox"].switch {
    width: 38px;
    border-radius: 11px;
  }
  .captcha input[type="checkbox"].switch:after {
    left: 2px;
    top: 2px;
    border-radius: 50%;
    width: 15px;
    height: 15px;
    background: var(--ab, var(--border));
    -webkit-transform: translateX(var(--x, 0));
    transform: translateX(var(--x, 0));
  }
  .captcha input[type="checkbox"].switch:checked {
    --ab: var(--active-inner);
    --x: 17px;
  }
  .captcha input[type="checkbox"].switch:disabled:not(:checked):after {
    opacity: 0.6;
  }
}
\`
document.getElementsByTagName('head')[0].appendChild(script)
function getrefreshtoken () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+"/getrefreshtoken",
    type: 'GET',
    success: function (data) {
      window.MV.rt = data
      window.MV.root.alert.show({
        type: 2,
        text: '系统触发了防御机制-Captcha策略，请进行人机验证！',
        cb: getcap
      })
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
function getcap () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+"/getcap",
    type: 'GET',
    data: {
      refreshtoken: window.MV.rt
    },
    success: function (data) {
      window.MV.recapq = data
      window.MV.root.alert.show({
        type: 3,
        text: '<div class="captcha"><input type="checkbox" class="captcha-check"> 我是人类 | I am human</div>',
        cb: () => {
          const captcha = window.MV.root.el.querySelector('.captcha-check')
          window.MV.dom.on('click', captcha, (e) => {
            setTimeout(() => {
              window.MV.root.alert.show({
                type: 2,
                text: '<img style="border-radius: 7px;background-color: #fff !important;height: 120px;" src="'+window.MV.root.conf.serverURL+'/getimgcap?refreshtoken='+window.MV.rt+'&recapq='+window.MV.recapq+'"><br/>请输入该化学结构式的（唯一）分子式<br/>Please type the (unique) molecular formula of the chemical structural formula<br/><input id="captcha-in"><br/>',
                cb: () => {
                  if (document.getElementById('captcha-in')) {
                    getaccesstoken()
                  }
                },
                ctxt: window.MV.root.i18n.submit
              })
            }, 1000)
          })
        }
      })
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
function getaccesstoken () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+'/getaccesstoken',
    type: 'GET',
    data: {
      refreshtoken: window.MV.rt,
      recapq: window.MV.recapq,
      recapans: document.getElementById('captcha-in').value
    },
    success: function (data) {
      if (data.capcode) {
          window.MV.root.error(data.capcode, data)
      } else {
        window.MV.accesstoken = data
        window.MV.root.postComment(window.MV.root, window.MV.root.postComment.callback)
        window.MV.root.alert.hide()
      }
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
getrefreshtoken()
`
/*********************************************************************************************** */
// Fetch触发器
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});
// Cron触发器
addEventListener("scheduled", event => {
  event.waitUntil(handleScheduled(event))
})
/*********************************************************************************************** */
async function handleScheduled(event) {
  await SecurityLevel("essentially_off")
  await CreateRoute()
}
/*********************************************************************************************** */
function SecurityLevel(lev) {
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/settings/security_level", {
    method: "PATCH",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
      "Content-Type": "application/json",
    },
    body: '{"value":"'+lev+'"}'
  }));
}
function Schedules(corn) {
  return fetch(new Request("https://api.cloudflare.com/client/v4/accounts/"+ACCOUNTID+"/workers/scripts/"+WORKERNAME+"/schedules", {
    method: "PUT",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
      "Content-Type": "application/json",
    },
    body: '[{"cron": "'+corn+'"}]'
  }));
}
function GETRoutes() {
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes", {
    method: "GET",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
    },
  }));
}
function DeleteRouteById(id) {
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes/"+id, {
    method: "DELETE",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
    },
  }));
}
function CreateRoute() {
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes", {
    method: "POST",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
      "Content-Type": "application/json",
    },
    body: '{"pattern":"'+WORKERROUTE+'","script":"'+WORKERNAME+'"}'
  }));
}
function GETAnalytics() {
  return fetch(new Request("https://api.cloudflare.com/client/v4/accounts/"+ACCOUNTID+"/storage/analytics", {
    method: "GET",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
    }
  }));
}
function GETFilters() {
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/filters", {
    method: "GET",
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
      "X-Auth-Email": AUTHEMAIL,
      "X-Auth-Key": AUTHKEY,
      "Content-Type": "application/json",
    },
  }));
}
async function GetPostBody(request){
  let formData = await request.formData()
  let body = {}
  for (let entry of formData.entries()) {
    body[entry[0]] = entry[1]
  }
  return body
}
function GetTimeMinutes(a,b){
  var dateDiff = a.getTime() - b.getTime();//时间差的毫秒数
  var leave1=dateDiff%(24*3600*1000) //计算天数后剩余的毫秒数
  //计算相差分钟数
  var leave2=leave1%(3600*1000) //计算小时数后剩余的毫秒数
  var minutes=Math.floor(leave2/(60*1000))//计算相差分钟数
  return minutes
}
// 下面这段 worker 函数全网首发，不堪回首
async function IPFSAdd(s){
 return await fetch(new Request(IPFSAPI+"/api/v0/add", {
        method: "POST",
        headers: {
          "accept":"application/json",
          "Content-Type":'multipart/form-data; boundary=----IPFSOHHHO20363.283362394857.60938.67369538564',
        },
        body:`------IPFSOHHHO20363.283362394857.60938.67369538564\r\n`+
        `Content-Disposition: form-data; name="path"\r\n`+
        `Content-Type: application/octet-stream\r\n\r\n`+
        s+
        `\r\n------IPFSOHHHO20363.283362394857.60938.67369538564--`
      }));
}
async function IPFSCat(hash){
    return await fetch("https://cloudflare-ipfs.com/ipfs/"+hash)
}
/***************************************************************************************** */
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
    padding: 'PKCS7Padding' //补全值
}

/**
 * 读取密钥key
 */
function getSecretKey(){
    return AESKEY || "abcdabcdabcdabcd";
}

/**
 * AES_128_CBC 加密 
 * 128位 
 * return base64
 */
function EnCryptionAES(data) {
    let key = AES_conf.key;
    let iv = AES_conf.iv;
    // let padding = AES_conf.padding;

    var cipherChunks = [];
    var cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    cipher.setAutoPadding(true);
    cipherChunks.push(cipher.update(data, 'utf8', 'base64'));
    cipherChunks.push(cipher.final('base64'));
    return cipherChunks.join('');
}

/**
 * 解密
 * return utf8
 */
function DeCryptionAES(data){

    let key = AES_conf.key;
    let iv = AES_conf.iv;
    // let padding = AES_conf.padding;

    var cipherChunks = [];
    var decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(true);
    cipherChunks.push(decipher.update(data, 'base64', 'utf8'));
    cipherChunks.push(decipher.final('utf8'));
    return cipherChunks.join('');
}


