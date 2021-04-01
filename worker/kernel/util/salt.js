function salt(n) {
  var str = "abcdefghijklmnopqrstuvwxyz0123456789";
  var result = "";
  for (var i = 0; i < n; i++) {
      result += str[parseInt(Math.random() * str.length)];
  }
  return result;
}
export default salt
