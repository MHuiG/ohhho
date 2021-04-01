function getTimeMinutes(a,b){
  var dateDiff = a.getTime() - b.getTime();//时间差的毫秒数
  var leave1=dateDiff%(24*3600*1000) //计算天数后剩余的毫秒数
  //计算相差分钟数
  var leave2=leave1%(3600*1000) //计算小时数后剩余的毫秒数
  var minutes=Math.floor(leave2/(60*1000))//计算相差分钟数
  return minutes
}
export default  getTimeMinutes