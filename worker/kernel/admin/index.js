import kernel from "../../kernel"
async function listAll(){
  let meta= await kernel.cf.kv.getMeta()
  let all=[]
  let data
  for (let index = 0; index < meta.key.length; index++) {
    const element = meta.key[index];
    let m =  meta.sub[element].h
    data = await kernel.ipfs.cat(m)
    for (let index = 0; index < data.length; index++) {
      const element = data[index];
      if(element.children){
        for (let j = 0; j < element.children.length; j++) {
          const c = element.children[j];
          all.push(c)
        }
        element.children=[]
      }
      all.push(element)
    }
  }
  all=all.sort(function(a, b) {
    return b.createdAt < a.createdAt ? -1 : 1
  })
  return all
}
async function changeData(data){
  let meta=await kernel.cf.kv.getMeta()
  let hash= meta.sub[data.url].h
  let c=await kernel.ipfs.cat(hash)
  for (let index = 0; index < c.length; index++) {
    const element = c[index];
    if (element.id==data.id) {
      c.splice(index,1,data);
      break
    }
    if (data.pid&&element.id==data.pid) {
      for (let j = 0; j < element.children.length; j++) {
        const ele = element.children[j];
        if (ele.id==data.id) {
          if (ele.id==data.id) {
            element.children.splice(j,1,data);
            break
          }
        }
      }
    }
  }
  let sc= await kernel.ipfs.add(JSON.stringify(c))
  meta.sub[data.url].h=sc.Hash
  await kernel.cf.kv.putMeta(meta)
  return c
}
async function deleteData(data){
  let cnum=0
  let meta=await kernel.cf.kv.getMeta()
  let hash= meta.sub[data.url].h
  let c=await kernel.ipfs.cat(hash)
  for (let index = 0; index < c.length; index++) {
    const element = c[index];
    if (element.id==data.id) {
      c.splice(index,1);
      if(element.children)
        cnum=element.children.length
      break
    }
    if (data.pid&&element.id==data.pid) {
      for (let j = 0; j < element.children.length; j++) {
        const ele = element.children[j];
        if (ele.id==data.id) {
          if (ele.id==data.id) {
            element.children.splice(j,1);
            break
          }
        }
      }
    }
  }

  let sc= await kernel.ipfs.add(JSON.stringify(c))
  meta.sub[data.url].h=sc.Hash
  if (data.pid) {
    meta.sub[data.url].s-=1
  }else{
    meta.sub[data.url].s-=(cnum+1)
    meta.sub[data.url].f-=1
  }

  await kernel.cf.kv.putMeta(meta)
  return c
}

let admin={
  listAll:listAll,
  changeData:changeData,
  deleteData:deleteData,
}
export default admin
