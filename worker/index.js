import kernel from './kernel'
const md5 = require('blueimp-md5')
const uaparser = require('ua-parser-js')

let ohhho_logstatus=0
async function handleRequest(event) {
  const request = event.request;
  const req = request;
  const urlStr = req.url;
  const urlObj = new URL(urlStr);
  const path = urlObj.href.substr(urlObj.origin.length);
  const CFConnectingIP=request.headers.get("CF-Connecting-IP")
  const XForwardedFor=request.headers.get("X-Forwarded-For")
  const CfIpcountry=request.headers.get("Cf-Ipcountry")
  const XRealIP=new Map(request.headers).get('x-real-ip')
  /************************************** */
  // 安全检查
  event.waitUntil(kernel.sec.securityCheckHead())
  /************************************** */
  try {
    if (path == "/favicon.ico") {
      return fetch("https://cdn.jsdelivr.net/npm/mhg@latest");
    }
    if (path.startsWith("/md")) {
      if(request.method=="POST"){
        let body=await kernel.util.getPostBody(request)
        return new Response(kernel.util.getMd(body.s), kernel.util.headers.js)
      }
    }
    if (path.startsWith("/comment")) {
      if(request.method=="POST"){
        let body=await kernel.util.getPostBody(request)
        body.ip = CFConnectingIP || XRealIP
        body.XForwardedFor = XForwardedFor
        body.CfIpcountry = CfIpcountry
        /************************************** */
        // 检测 request  IP-Time
        // 15min
        let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
        if(ohhhho_under_attack){
          let ans=await kernel.sec.securityCheckPost(body)
          if(ans!=true){
            return ans
          }
        }else{
          event.waitUntil(kernel.sec.securityCheckPost(body))
        }
        // 检测大文本攻击
        var la =body.comment?body.comment.length:0
        var lb =body.link?body.link.length:0
        var lc =body.nick?body.nick.length:0
        var ln = Math.max( la,lb,lc )
        if(ln>1000000){
          return new Response("那太大了", kernel.util.headers.js);
        }
        /************************************** */

        let Item = toItem(body)
        event.waitUntil(SaveComment(Item,body))
        let it = getIt(Item)
        return new Response(JSON.stringify(it), kernel.util.headers.js)
      }else if(request.method=="GET"){
        const type = urlObj.searchParams.get('type')
        const path = urlObj.searchParams.get('path')
        let meta = await kernel.cf.kv.getMeta()
        if(type=="count"){
          let count=0
          if(meta.sub[path]){
            count=meta.sub[path].s
          }
          return new Response(JSON.stringify(count), kernel.util.headers.js)
        }else if(type=="totalPages"){
          let count=0
          if(meta.sub[path]){
            count=meta.sub[path].f
          }
          const pageSize = urlObj.searchParams.get('pageSize')
          let num=Math.ceil(count / pageSize)
          return new Response(JSON.stringify(num), kernel.util.headers.js)
        }else{
          const pageSize = urlObj.searchParams.get('pageSize')
          const page = urlObj.searchParams.get('page')
          let c=0
          if(meta.sub[path]){
            let hash= meta.sub[path].h
            c=await kernel.ipfs.cat(hash)
          }
          if(c){
            let p=[]
            for (let i = 0; i < c.length; i++) {
              let ele = getIt(c[i]);
              if(ele.children){
                for (let j = 0; j < ele.children.length; j++) {
                  const it = ele.children[j];
                  if(!it.approval){
                    ele.children.splice(j,1);
                  }
                }
              }
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
            return new Response(JSON.stringify(q), kernel.util.headers.js)
          }
          return new Response(JSON.stringify({}), kernel.util.headers.js)
        }
      }
    }
    /*********************************************************************************************** */
    // Captcha
    if (path.startsWith("/getrefreshtoken")) {
      const RT = kernel.captcha.getRefreshToken()
      return new Response(RT, kernel.util.headers.js)
    }
    if (path.startsWith("/getaccesstoken")) {
      const RToken = urlObj.searchParams.get('refreshtoken')
      let recapq=urlObj.searchParams.get('recapq')
      let recapans=urlObj.searchParams.get('recapans')
      const AT = await kernel.captcha.getAccessToken(RToken,recapq,recapans)
      return new Response(AT, kernel.util.headers.js)
    }
    if (path.startsWith("/getcap")) {
      let RToken=urlObj.searchParams.get('refreshtoken')
      const recapq = await kernel.captcha.getCap(RToken)
      return new Response(recapq, kernel.util.headers.js)
    }
    if (path.startsWith("/getimgcap")) {
      let RToken=urlObj.searchParams.get('refreshtoken')
      let recapq=urlObj.searchParams.get('recapq')
      return kernel.captcha.getCapImg(RToken,recapq)
    }
    if (path.startsWith("/ChallengeCaptcha")) {
      if(typeof CAPTCHAAPI != "undefined"){
          let sc=await fetch(new Request(CAPTCHAAPI+"/ChallengeCaptchaScript"));
          sc=await sc.text()
          return new Response(sc, kernel.util.headers.js);
      }
      return new Response(kernel.page.captcha, kernel.util.headers.js);
    }
    /*********************************************************************************************** */
    if (path.startsWith("/ohhho")) {
      if (kernel.util.getCookie(request, "password") == md5(PASSWORD) && kernel.util.getCookie(request, "username") == md5(USERNAME)) {
        ohhho_logstatus = 1
      }else{
        return new Response(kernel.page.login, kernel.util.headers.html)
      }
      if(!ohhho_logstatus){
        return new Response(kernel.page.login, kernel.util.headers.html)
      }
      if (path.startsWith("/ohhho/dash")) {
        return new Response(kernel.page.dash, kernel.util.headers.html)
      }
      if (path.startsWith("/ohhho/ListAll")) {
        let all= await kernel.admin.listAll()
        return new Response(JSON.stringify(all), kernel.util.headers.js);
        
      }
      if (path.startsWith("/ohhho/NodeChange")) {
        if(request.method=="POST"){
          let body=await kernel.util.getPostBody(request)
          let data=JSON.parse(body.data)
          let c=await kernel.admin.changeData(data)
          return new Response(JSON.stringify(c), kernel.util.headers.json);
        }
      }
      if (path.startsWith("/ohhho/NodeDel")) {
        if(request.method=="POST"){
          let body=await kernel.util.getPostBody(request)
          let data=JSON.parse(body.data)
          let c=await kernel.admin.deleteData(data)
          return new Response(JSON.stringify(c), kernel.util.headers.json);
        }
      }
      return Response.redirect(OHHHOPATH+"/ohhho/dash", 302)
    }
    /*********************************************************************************************** */
    if (path.startsWith("/ws")) {
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader !== "websocket") {
        return new Response("Expected websocket", { status: 400 });
      }

      const [client, server] = Object.values(new WebSocketPair());
      await handleWebSocketSession(server,event);

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }
    /*********************************************************************************************** */
    return new Response("Hello world", kernel.util.headers.js);
  } catch (e) {
    console.log(e);
    return new Response("!!Error!!"+e, kernel.util.headers.html);
  }
}

var NewID = function() {
  return kernel.util.salt(24)
}

var toItem = function(body){
  let Item={}
  Item.approval=true // 批准状态
  Item.comment=body.comment
  Item.commentHtml=kernel.util.getMd(body.comment)
  Item.createdAt=new Date()
  Item.mail=body.mail
  Item.mailMd5=md5(body.mail)
  Item.ua=body.ua
  const ua=uaparser(Item.ua)
  Item.browser=ua.browser
  Item.os=ua.os
  Item.ip=body.ip
  Item.id=NewID()
  Item.link=kernel.util.XSS(body.link)
  Item.nick=kernel.util.XSS(body.nick)
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
async function SaveComment(Item,body){
    let ls=[]
    let meta= await kernel.cf.kv.getMeta()
    if(meta.key.indexOf(Item.url)!=-1){
      let hash=meta.sub[Item.url].h
      ls=await kernel.ipfs.cat(hash)
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
    let sc= await kernel.ipfs.add(JSON.stringify(ls))
    let hash=sc.Hash
    if(meta.key.indexOf(Item.url)==-1){
      meta.key.push(Item.url)
      meta.sub[Item.url]={}
      meta.sub[Item.url].h=hash
      meta.sub[Item.url].s=1
      meta.sub[Item.url].f=1
    }else{
      meta.sub[Item.url].h=hash
      meta.sub[Item.url].s+=1
      if (!Item.pid) {
        meta.sub[Item.url].f+=1
      }
    }
    let p={}
    p.ip=body.ip
    p.XForwardedFor=body.XForwardedFor
    p.CfIpcountry=body.CfIpcountry
    p.time=new Date()
    for (const it of meta.sec.IPTime) {
     let minutes= kernel.util.getTimeMinutes(p.time,new Date(it.time))
     if(minutes>15){
       // 移除过时数据
      var index = meta.sec.IPTime.indexOf(it)
      if (index > -1) {
        meta.sec.IPTime.splice(index, 1);
      }
     }
    }
    meta.sec.IPTime.push(p)
    await kernel.cf.kv.putMeta(meta)
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
}

/*********************************************************************************************** */
// Fetch触发器
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});
// Cron触发器
addEventListener("scheduled", event => {
  event.waitUntil(handleScheduled(event))
})
/*********************************************************************************************** */
async function handleScheduled(event) {
  await kernel.cf.api.setSecurityLevel("essentially_off")
  await kernel.cf.api.createRoute()
}
/*********************************************************************************************** */

/*********************************************************************************************** */
async function handleWebSocketSession(websocket,event) {
  const request = event.request;
  const CFConnectingIP=request.headers.get("CF-Connecting-IP")
  const XForwardedFor=request.headers.get("X-Forwarded-For")
  const CfIpcountry=request.headers.get("Cf-Ipcountry")
  const XRealIP=new Map(request.headers).get('x-real-ip')
  websocket.accept();
  // 连接测试 回传信息
  setInterval(()=>{
    websocket.send(JSON.stringify({"code":0,"msg":"Connection test",tz: new Date() }));
  },5000)
  // 连接开始
  websocket.send(JSON.stringify({"code":200,"msg":"Connection start",tz: new Date() }));

  websocket.addEventListener("message", async ({ data }) => {
    try {
      let m = JSON.parse(data)
      if(m.opt=="previewEvt"){
        websocket.send(JSON.stringify({"code":1,"msg":kernel.util.getMd(m.msg),tz: new Date() }));
      }else if(m.opt=="TotalPages"){
        let meta = await kernel.cf.kv.getMeta()
        let count=0
        if(meta.sub[m.path]){
          count=meta.sub[m.path].f
        }
        let num=Math.ceil(count / m.pageSize)
        websocket.send(JSON.stringify({"code":2,"count":count,"TotalPages":num,tz: new Date() }));
      }else if(m.opt=="ParentList"){
        const pageSize = m.pageSize
        const page = m.page
        const path = m.path
        let meta = await kernel.cf.kv.getMeta()
        let c=0
        if(meta.sub[path]){
          let hash= meta.sub[path].h
          c=await kernel.ipfs.cat(hash)
        }
        if(c){
          let p=[]
          for (let i = 0; i < c.length; i++) {
            let ele = getIt(c[i]);
            if(ele.children){
              for (let j = 0; j < ele.children.length; j++) {
                const it = ele.children[j];
                if(!it.approval){
                  ele.children.splice(j,1);
                }
              }
            }
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
          websocket.send(JSON.stringify({"code":3,"msg":q,tz: new Date() }));
        }
        websocket.send(JSON.stringify({"code":3,"msg":{},tz: new Date() }));
      }else if(m.opt=="postComment"){
        let sec=1
        let body=m.msg
        body.ip = CFConnectingIP || XRealIP
        body.XForwardedFor = XForwardedFor
        body.CfIpcountry = CfIpcountry
        /************************************** */
        // 检测 request  IP-Time
        // 15min
        let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
        if(ohhhho_under_attack){
          let ans=await kernel.sec.securityCheckPostWS(body)
          if(ans.code!=200){
            websocket.send(JSON.stringify({"code":403,"msg":ans,tz: new Date() }));
            sec=0
          }
        }else{
          event.waitUntil(kernel.sec.securityCheckPostWS(body))
        }
        // 检测大文本攻击
        var la =body.comment?body.comment.length:0
        var lb =body.link?body.link.length:0
        var lc =body.nick?body.nick.length:0
        var ln = Math.max( la,lb,lc )
        if(ln>1000000){
          websocket.send(JSON.stringify({"code":403,"msg":"那太大了",tz: new Date() }));
          sec=0
        }
        /************************************** */
        if(sec){
          let Item = toItem(body)
          event.waitUntil(SaveComment(Item,body))
          let it = getIt(Item)
          websocket.send(JSON.stringify({"code":4,"msg":it,tz: new Date() }))
        }
      }else{
        websocket.send(JSON.stringify({"code":404,"msg":"Unknown message received",tz: new Date() }));
      }
    } catch (error) {
      websocket.send(JSON.stringify({"code":500,"msg":error,tz: new Date() }));
    }
  });
  websocket.addEventListener("close", async (evt) => {
    // console.log(evt);
  });
}
/*********************************************************************************************** */
