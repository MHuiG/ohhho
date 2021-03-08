import Factory from './Factory'
import { VERSION } from './Default'
const ohhho = (option) => {
  if (!window.MV) {
    console.log('%c ohhho %c v' + VERSION + ' ', 'color: white; background: #0078E7; padding:5px 0;', 'padding:4px;border:1px solid #0078E7;')
    window.MV = Object.create(null)
    window.MV.v = VERSION
  }
  return new Factory(option)
}
module.exports = ohhho
module.exports.default = ohhho