async function getPostBody(request){
  let formData = await request.formData()
  let body = {}
  for (let entry of formData.entries()) {
    body[entry[0]] = entry[1]
  }
  return body
}
export default getPostBody