let header_cf={
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
  "X-Auth-Email": AUTHEMAIL,
  "X-Auth-Key": AUTHKEY,
  "Content-Type":"application/json",
}
let api={
  setSecurityLevel:function (lev) {
    return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/settings/security_level", {
      method: "PATCH",
      headers: header_cf,
      body: '{"value":"'+lev+'"}'
    }));
  },
  setSchedule:function (cron) {
    return fetch(new Request("https://api.cloudflare.com/client/v4/accounts/"+ACCOUNTID+"/workers/scripts/"+WORKERNAME+"/schedules", {
      method: "PUT",
      headers: header_cf,
      body: '[{"cron": "'+cron+'"}]'
    }));
  },
  getRoutes:function () {
    return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes", {
      method: "GET",
      headers: header_cf,
    }));
  },
  deleteRouteById:function (id) {
    return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes/"+id, {
      method: "DELETE",
      headers: header_cf,
    }));
  },
  createRoute:function () {
    return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/workers/routes", {
      method: "POST",
      headers: header_cf,
      body: '{"pattern":"'+WORKERROUTE+'","script":"'+WORKERNAME+'"}'
    }));
  },
  getAnalytics:function () {
    return fetch(new Request("https://api.cloudflare.com/client/v4/accounts/"+ACCOUNTID+"/storage/analytics", {
      method: "GET",
      headers: header_cf
    }));
  },
  getFilters:function () {
    return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/filters", {
      method: "GET",
      headers: header_cf,
    }));
  },
}
export default api