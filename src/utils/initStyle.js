const initStyle = (root) => {
  if (!root.conf.closeCSS) {
    require('../style/style.scss')
    require('../style/md.scss')
    require('../style/github.scss')
  }
}
module.exports = initStyle
