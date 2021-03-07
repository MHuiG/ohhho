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
  console.log(path);
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
        body.ip=new Map(request.headers).get('x-real-ip')
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
          await OHHHO.delete(Item.url)
        }else{
          ls.push(Item)
        }
        await OHHHO.put(Item.url,JSON.stringify(ls))
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
              p.push(ele)
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



var RID = function() {
  var str = "abcdefghijklmnopqrstuvwxyz0123456789";
  var result = "";
  for(var i = 0; i < 24; i++) {
      result += str[parseInt(Math.random() * str.length)];
  }
  return result;
}

var toItem = function(body){
  let Item={}
  Item.comment=body.comment
  Item.createdAt=new Date()
  Item.mail=body.mail
  Item.ua=body.ua
  Item.ip=body.ip
  Item.id=RID()
  Item.link=body.link
  Item.nick=body.nick
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
  it.comment=md(XSS(Item.comment))
  it.createdAt=Item.createdAt
  it.mailMd5=md5(Item.mail)
  const ua=uaparser(Item.ua)
  it.browser=ua.browser
  it.os=ua.os
  it.id=Item.id
  if(Item.nick){
    it.nick=XSS(Item.nick)
  }
  if (Item.link) {
    it.link=XSS(Item.link)
  }
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