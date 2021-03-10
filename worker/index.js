import md from "marked";
const md5 = require('blueimp-md5')
const uaparser = require('ua-parser-js')
const highligher = require('highlight.js')

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
import xss from 'xss'
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

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

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
  const privatek = "kjerwahfvfiuwehgfiuwrgfuisegfuiwdgfiuegwfdsi"
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
        const formData = await request.formData()
        const body = {}
        for (const entry of formData.entries()) {
          body[entry[0]] = entry[1]
        }
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
         let itTime = new Date(it.time)
         var dateDiff = p.time.getTime() - itTime.getTime();//时间差的毫秒数
         var leave1=dateDiff%(24*3600*1000) //计算天数后剩余的毫秒数
         //计算相差分钟数
         var leave2=leave1%(3600*1000) //计算小时数后剩余的毫秒数
         var minutes=Math.floor(leave2/(60*1000))//计算相差分钟数
         
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

          let filters = await fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/filters", {
            method: "GET",
            headers: {
              "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
              "X-Auth-Email": AUTHEMAIL,
              "X-Auth-Key": AUTHKEY,
              "Content-Type": "application/json",
            },
          }));
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
        if(q.length>5||q.length>0){
          let ans=await CheckCaptcha(body.refreshtoken,privatek,body.recapq,body.recapans)
          if(ans!=true){
            return ans
          }
        }
        if(q.length>16){
          let wait_attack=await OHHHO.get("ohhho_attack")
          if(wait_attack){
            wait_attack=JSON.parse(wait_attack)
            var dateDiff = new Date().getTime() - new Date(wait_attack.time).getTime();//时间差的毫秒数
            var leave1=dateDiff%(24*3600*1000) //计算天数后剩余的毫秒数
            //计算相差分钟数
            var leave2=leave1%(3600*1000) //计算小时数后剩余的毫秒数
            var minutes=Math.floor(leave2/(60*1000))//计算相差分钟数
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
          await fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/settings/security_level", {
            method: "PATCH",
            headers: {
              "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
              "X-Auth-Email": AUTHEMAIL,
              "X-Auth-Key": AUTHKEY,
              "Content-Type": "application/json",
            },
            body: '{"value":"under_attack"}'
          }));
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
        const c= await OHHHO.get(Item.url)
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
        await OHHHO.put(Item.url,JSON.stringify(ls))
        try{
          await fetch(new Request(APIPATH, {
            method: "POST",
            headers: {
              "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
            },
            body: JSON.stringify(Item)
          }));
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
        const c= await OHHHO.get(path)
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
    if (path.startsWith("/getcap")) {
      let ans=await CheckRT(urlObj.searchParams.get('refreshtoken'),privatek)
      if(ans!=true){
        return ans
      }
      let capi=await GetCapJson()
      capi=capi["0"]
      // const id = randomNum(0,10185)
      const id = 0
      let _CAP = {
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
    if (path.startsWith("/test")) {
      
      return fetch(`https://raw.githubusercontent.com/MHuiG/Captcha-chemi/master/img/5815-08-7.gif`)


      // let refreshtoken= urlObj.searchParams.get('refreshtoken')
      // let recapq= urlObj.searchParams.get('recapq')
      // let recapans= urlObj.searchParams.get('recapans')
      // let ans=await CheckCaptcha(refreshtoken,privatek,recapq,recapans)
      // if(ans!=true){
      //   return ans
      // }
    }
    /*********************************************************************************************** */
    return new Response("Hello world", headers_init);
  } catch (e) {
    console.log(e);
    return new Response("error:"+e, {
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
async function CheckCaptcha(refreshtoken,privatek,recapq,recapans) {
  let ans=await CheckRT(refreshtoken,privatek)
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
    if(await checkcap(reqa["capid"],recapans)){
        let banlist = await JSON.parse(await OHHHO.get("ohhho_banrt")) || []
        banlist.push(refreshtoken)
        await OHHHO.put("ohhho_banrt",await JSON.stringify(banlist),{expirationTtl: 5*60})
        return true
    }else{
      return returnc(5)
    }
  }else{
      return returnc(3)
  }
}
async function CheckRT(refreshtoken,privatek) {
  try { 
    await JSON.parse(Decrypt(refreshtoken, privatek))
  } catch (e) { 
    return returnc(0)
  }
  const _RT = await JSON.parse(Decrypt(refreshtoken, privatek))
  if (checktime(_RT)) {
    if(await checkban(refreshtoken, privatek)){
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
async function checkcap(q,ans){
  let capi=await GetCapJson()
  capi=capi["0"]
  if(capi[q][2] == ans) return true
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
      "CapthcaID丢失"
  ]
  const as = {
      code: i+1,
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
  const r = await JSON.parse(await OHHHO.get("ohhho_banrt"))
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
/*********************************************************************************************** */
