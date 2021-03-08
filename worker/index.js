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
        // 15min 50
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
        if(num>30){
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
