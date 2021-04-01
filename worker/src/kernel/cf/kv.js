import kernel from "../../kernel"
/*
{
  "sec":{
    "IPTime":[{"ip":"1.1.1.1","XForwardedFor":null,"CfIpcountry":"CN","time":"2021-03-23T01:57:37.076Z"}],
  },
  "key":["/"],
  "sub":{
    "/":{
      "h":"QmSC2VmvGQ4864GSkW87U2UAGZa4QbCDAy2aChjwqNNHU123",
      "s":2,
      "f":2
    },
  }
}
*/
async function putMeta(meta){
  let sc= await kernel.ipfs.add(JSON.stringify(meta))
  if(typeof I_Understand_The_Risks != "undefined"){
    await PutIPFSHash(sc.Hash)
  }else{
    await OHHHO.put("OHHHO_Hash",sc.Hash)
  }
}
async function getMeta(){
  let hash = 0
  if(typeof I_Understand_The_Risks != "undefined"){
    hash = await GetIPFSHash()
  }else{
    hash = await OHHHO.get("OHHHO_Hash")
  }
  if(hash){
    let c=await kernel.ipfs.cat(hash)
    return c
  }
  return {
      "sec":{
        "IPTime":[],
      },
      "key":[],
      "sub":{
      }
    }
}
async function GetIPFSHash(){
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
    let res=expression.match(/OHHHO-IPFS-(.*)-OHHHO-IPFS/i)
    if(res.length==2){
      return res[1]
    }
  }
  return 0
}
async function PutIPFSHash(IPFSHASH){
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
    let res=expression.match(/OHHHO-IPFS-(.*)-OHHHO-IPFS/i)
    if(res.length==2){
      item.expression=expression.replace(/OHHHO-IPFS-(.*)-OHHHO-IPFS/, "OHHHO-IPFS-"+IPFSHASH+"-OHHHO-IPFS")
      return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/filters", {
        method: "PUT",
        headers: {
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 Edg/88.0.100.0",
          "X-Auth-Email": AUTHEMAIL,
          "X-Auth-Key": AUTHKEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([item])
      }));
    }
  }
  let expression = `(http.cookie eq \\"OHHHO-IPFS-${IPFSHASH}-OHHHO-IPFS\\")`
  return fetch(new Request("https://api.cloudflare.com/client/v4/zones/"+ZONEID+"/firewall/rules", {
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
let kv={
  putMeta:putMeta,
  getMeta:getMeta,
}
export default kv