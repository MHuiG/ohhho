import md from "marked";
import XSS from './XSS'
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
function getMd(o){
  return md(XSS(o))
}
export default getMd