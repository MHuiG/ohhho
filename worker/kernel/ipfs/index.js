import kernel from "../../kernel"
let ipfs = {
  add: async function (s) {
    s=kernel.crypto.EnCryptionAES(s)
    let sc= await fetch(
      new Request(IPFSAPI + "/api/v0/add", {
        method: "POST",
        headers: {
          accept: "application/json",
          "Content-Type":
            "multipart/form-data; boundary=----IPFSOHHHO20363.283362394857.60938.67369538564",
        },
        body:
          `------IPFSOHHHO20363.283362394857.60938.67369538564\r\n` +
          `Content-Disposition: form-data; name="path"\r\n` +
          `Content-Type: application/octet-stream\r\n\r\n` +
          s +
          `\r\n------IPFSOHHHO20363.283362394857.60938.67369538564--`,
      })
    );
    sc=await sc.json()
    return sc
  },
  cat: async function (hash) {
    let data=await fetch("https://cloudflare-ipfs.com/ipfs/" + hash);
    data=await data.text()
    data= kernel.crypto.DeCryptionAES(data)
    data= JSON.parse(data)
    return data
  },
};
export default ipfs;
