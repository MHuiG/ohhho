import dom from './plugins/dom'
const inputs = (root) => {
  root.inputs = Object.create(null)
  root.mapping = {
    veditor: 'comment',
    vnick: 'nick',
    vlink: 'link',
    vmail: 'mail'
  }
  for (const i in root.mapping) {
    if (root.mapping.hasOwnProperty(i)) {
      const _v = root.mapping[i]
      const _el = root.el.querySelector(`.${i}`)
      root.inputs[_v] = _el
      dom.on('input', _el, (e) => {
        root.C[_v] = _el.value
      })
      if (i == 'veditor') {
        dom.on('input', _el, (e) => {
          console.log(_el.value.length)
          window.MV.veditorLength = _el.value.length
          if (!window.MV.veditorPassInterval) {
            window.MV.veditorPassInterval = 1
            const veditorInterval = setInterval(() => {
              if (window.MV.veditorLength != _el.value.length) {
                window.MV.veditorLength = _el.value.length
                window.MV.veditorPass = 0
              } else {
                window.MV.veditorPass = 1
              }
              if (window.MV.veditorPass) {
                root.previewEvt(root)
                clearInterval(veditorInterval)
                window.MV.veditorPass = 0
                window.MV.veditorPassInterval = 0
              }
            }, 2500)
          }
        })
      }
    }
  }
}
module.exports = inputs
