import kernel from "../../kernel"
async function securityCheckHead(){
  let analytics=await kernel.cf.api.getAnalytics()
  let result=(await analytics.json()).result
  if(result.totals.requests>30000){
    await kernel.cf.api.setSecurityLevel("under_attack")
    await kernel.cf.api.setSchedule("0 21 * * *")
  }
  if(result.totals.requests>35000){
    let routes=await kernel.cf.api.getRoutes()
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
      await kernel.cf.api.deleteRouteById(routeid)
    }
  }
}
async function securityCheckPost(body){
  let meta=await kernel.cf.kv.getMeta()
  const now = new Date()
  let p={}
  p.ip=body.ip
  p.XForwardedFor=body.XForwardedFor
  p.CfIpcountry=body.CfIpcountry
  p.time=new Date()
  let num=0
  for (const it of meta.sec.IPTime) {
   let minutes=kernel.util.getTimeMinutes(p.time,new Date(it.time))
   if(minutes>15){
     // 移除过时数据
    var index = meta.sec.IPTime.indexOf(it)
    if (index > -1) {
      meta.sec.IPTime.splice(index, 1);
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

    let filters = await kernel.cf.api.getFilters()
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
    let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
    if(!ohhhho_under_attack){
      await OHHHO.put("ohhhho_under_attack","1", { expirationTtl: 2 * 60 * 60 })
    }
    return new Response("本站正遭受攻击，请稍后再试！", kernel.util.headers.js);
  }
  if(meta.sec.IPTime.length>=10){
    let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
    if(!ohhhho_under_attack){
      await OHHHO.put("ohhhho_under_attack","1", { expirationTtl: 2 * 60 * 60 })
    }
    if(typeof CAPTCHAAPI != "undefined"){
      let sc=await fetch(new Request(CAPTCHAAPI+"/CheckChallengeCaptcha?accesstoken="+body.accesstoken, {
        method: "GET",
        headers: {
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
        },
      }));
      sc=await sc.text()
      if(sc!="OK"){
        return new Response(sc, kernel.util.headers.js);
      }
    }else{
      let ans=await kernel.captcha.checkAccessToken(body.accesstoken)
      if(ans!=true){
        return new Response(ans, kernel.util.headers.json)
      }else{
        return true
      }
    }
  }
  if(meta.sec.IPTime.length>=12){
    let wait_attack=await OHHHO.get("ohhho_attack")
    if(wait_attack){
      wait_attack=JSON.parse(wait_attack)
      var minutes=kernel.util.getTimeMinutes(new Date(),new Date(wait_attack.time))
      if(minutes>1){
        await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
      }else{
        return new Response("系统触发了防御机制-强制等待策略，请一分钟后重试！", kernel.util.headers.js);
      }
    }else{
      await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
    }
  }
  if(meta.sec.IPTime.length>20){
    await kernel.cf.api.setSecurityLevel("under_attack")
    await kernel.cf.api.setSchedule("0 21 * * *")
    return new Response("本站正遭受攻击，请稍后再试！！", kernel.util.headers.js);
  }
}

async function securityCheckPostWS(body){
  let meta=await kernel.cf.kv.getMeta()
  const now = new Date()
  let p={}
  p.ip=body.ip
  p.XForwardedFor=body.XForwardedFor
  p.CfIpcountry=body.CfIpcountry
  p.time=new Date()
  let num=0
  for (const it of meta.sec.IPTime) {
   let minutes=kernel.util.getTimeMinutes(p.time,new Date(it.time))
   if(minutes>15){
     // 移除过时数据
    var index = meta.sec.IPTime.indexOf(it)
    if (index > -1) {
      meta.sec.IPTime.splice(index, 1);
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

    let filters = await kernel.cf.api.getFilters()
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
    let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
    if(!ohhhho_under_attack){
      await OHHHO.put("ohhhho_under_attack","1", { expirationTtl: 2 * 60 * 60 })
    }
    return {
      code:0,
      msg:"本站正遭受攻击，请稍后再试！"
    };
  }
  if(meta.sec.IPTime.length>=10){
    let ohhhho_under_attack=await OHHHO.get("ohhhho_under_attack")
    if(!ohhhho_under_attack){
      await OHHHO.put("ohhhho_under_attack","1", { expirationTtl: 2 * 60 * 60 })
    }
    if(typeof CAPTCHAAPI != "undefined"){
      let sc=await fetch(new Request(CAPTCHAAPI+"/CheckChallengeCaptcha?accesstoken="+body.accesstoken, {
        method: "GET",
        headers: {
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
        },
      }));
      sc=await sc.text()
      if(sc!="OK"){
        return {
          code:506,
          msg:JSON.parse(sc)
        };
      }
    }else{
      let ans=await kernel.captcha.checkAccessToken(body.accesstoken)
      if(ans!=true){
        return {
          code:506,
          msg:ans
        };
      }else{
        return {
          code:200
        };
      }
    }
  }
  if(meta.sec.IPTime.length>=12){
    let wait_attack=await OHHHO.get("ohhho_attack")
    if(wait_attack){
      wait_attack=JSON.parse(wait_attack)
      var minutes=kernel.util.getTimeMinutes(new Date(),new Date(wait_attack.time))
      if(minutes>1){
        await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
      }else{
        return {
          code:0,
          msg:"系统触发了防御机制-强制等待策略，请一分钟后重试！"
        };
      }
    }else{
      await OHHHO.put("ohhho_attack",JSON.stringify({"time":new Date()}))
    }
  }
  if(meta.sec.IPTime.length>20){
    await kernel.cf.api.setSecurityLevel("under_attack")
    await kernel.cf.api.setSchedule("0 21 * * *")
    return {
      code:0,
      msg:"本站正遭受攻击，请稍后再试！！"
    };
  }
  return {
    code:200
  };
}

let sec={
  securityCheckHead:securityCheckHead,
  securityCheckPost:securityCheckPost,
  securityCheckPostWS:securityCheckPostWS,
}
export default sec
