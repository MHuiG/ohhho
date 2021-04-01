let captcha=`
var script = document.createElement('style')
script.innerText=\`
.captcha {
  color: var(--ohhho-mark-text);
  border: 1px solid #c5c5c5;
  width: 198px;
  margin: 0 auto;
  height: 50px;
  padding-top: 15px;
  border-radius: 7px;
}
@supports (-webkit-appearance: none) or (-moz-appearance: none) {
  .captcha input[type="checkbox"] {
    --active: #275efe;
    --active-inner: #fff;
    --focus: 2px rgba(39, 94, 254, 0.3);
    --border: #bbc1e1;
    --border-hover: #275efe;
    --background: #fff;
    --disabled: #f6f8ff;
    --disabled-inner: #e1e6f9;
    -webkit-appearance: none;
    -moz-appearance: none;
    height: 21px;
    outline: none;
    display: inline-block;
    vertical-align: top;
    position: relative;
    margin: 0;
    cursor: pointer;
    border: 1px solid var(--bc, var(--border));
    background: var(--b, var(--background));
    -webkit-transition: background 0.3s, border-color 0.3s, box-shadow 0.2s;
    transition: background 0.3s, border-color 0.3s, box-shadow 0.2s;
  }
  .captcha input[type="checkbox"]:after {
    content: "";
    display: block;
    left: 0;
    top: 0;
    position: absolute;
    -webkit-transition: opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
    transition: opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
    transition: transform var(--d-t, 0.3s) var(--d-t-e, ease),
      opacity var(--d-o, 0.2s);
    transition: transform var(--d-t, 0.3s) var(--d-t-e, ease),
      opacity var(--d-o, 0.2s),
      -webkit-transform var(--d-t, 0.3s) var(--d-t-e, ease);
  }
  .captcha input[type="checkbox"]:checked {
    --b: var(--active);
    --bc: var(--active);
    --d-o: 0.3s;
    --d-t: 0.6s;
    --d-t-e: cubic-bezier(0.2, 0.85, 0.32, 1.2);
  }
  .captcha input[type="checkbox"]:disabled,
  .captcha input[type="checkbox"]:disabled:checked {
    --b: var(--disabled-inner);
    --bc: var(--border);
  }
  .captcha input[type="checkbox"]:disabled + label {
    cursor: not-allowed;
  }
  .captcha input[type="checkbox"]:hover:not(:checked):not(:disabled) {
    --bc: var(--border-hover);
  }
  .captcha input[type="checkbox"]:focus,
  .captcha input[type="radio"]:focus {
    box-shadow: 0 0 0 var(--focus);
  }
  .captcha input[type="checkbox"]:not(.switch),
  .captcha input[type="radio"]:not(.switch) {
    width: 21px;
  }
  .captcha input[type="checkbox"]:not(.switch):after,
  .captcha input[type="radio"]:not(.switch):after {
    opacity: var(--o, 0);
  }
  .captcha input[type="checkbox"]:not(.switch):checked {
    --o: 1;
  }
  .captcha input[type="checkbox"] + label {
    font-size: 14px;
    line-height: 21px;
    display: inline-block;
    vertical-align: top;
    cursor: pointer;
    margin-left: 4px;
  }

  .captcha input[type="checkbox"]:not(.switch) {
    border-radius: 7px;
  }
  .captcha input[type="checkbox"]:not(.switch):after {
    width: 5px;
    height: 9px;
    border: 2px solid var(--active-inner);
    border-top: 0;
    border-left: 0;
    left: 7px;
    top: 4px;
    -webkit-transform: rotate(var(--r, 20deg));
    transform: rotate(var(--r, 20deg));
  }
  .captcha input[type="checkbox"]:not(.switch):checked {
    --r: 43deg;
  }
  .captcha input[type="checkbox"].switch {
    width: 38px;
    border-radius: 11px;
  }
  .captcha input[type="checkbox"].switch:after {
    left: 2px;
    top: 2px;
    border-radius: 50%;
    width: 15px;
    height: 15px;
    background: var(--ab, var(--border));
    -webkit-transform: translateX(var(--x, 0));
    transform: translateX(var(--x, 0));
  }
  .captcha input[type="checkbox"].switch:checked {
    --ab: var(--active-inner);
    --x: 17px;
  }
  .captcha input[type="checkbox"].switch:disabled:not(:checked):after {
    opacity: 0.6;
  }
}
\`
document.getElementsByTagName('head')[0].appendChild(script)
function getrefreshtoken () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+"/getrefreshtoken",
    type: 'GET',
    success: function (data) {
      window.MV.rt = data
      window.MV.root.alert.show({
        type: 2,
        text: '系统触发了防御机制-Captcha策略，请进行人机验证！',
        cb: getcap
      })
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
function getcap () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+"/getcap",
    type: 'GET',
    data: {
      refreshtoken: window.MV.rt
    },
    success: function (data) {
      window.MV.recapq = data
      window.MV.root.alert.show({
        type: 3,
        text: '<div class="captcha"><input type="checkbox" class="captcha-check"> 我是人类 | I am human</div>',
        cb: () => {
          const captcha = window.MV.root.el.querySelector('.captcha-check')
          window.MV.dom.on('click', captcha, (e) => {
            setTimeout(() => {
              window.MV.root.alert.show({
                type: 2,
                text: '<img style="border-radius: 7px;background-color: #fff !important;height: 120px;" src="'+window.MV.root.conf.serverURL+'/getimgcap?refreshtoken='+window.MV.rt+'&recapq='+window.MV.recapq+'"><br/>请输入该化学结构式的（唯一）分子式<br/>Please type the (unique) molecular formula of the chemical structural formula<br/><input id="captcha-in"><br/>',
                cb: () => {
                  if (document.getElementById('captcha-in')) {
                    getaccesstoken()
                  }
                },
                ctxt: window.MV.root.i18n.submit
              })
            }, 1000)
          })
        }
      })
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
function getaccesstoken () {
  window.MV.ajax({
    url: window.MV.root.conf.serverURL+'/getaccesstoken',
    type: 'GET',
    data: {
      refreshtoken: window.MV.rt,
      recapq: window.MV.recapq,
      recapans: document.getElementById('captcha-in').value
    },
    success: function (data) {
      if (data.capcode) {
          window.MV.root.error(data.capcode, data)
      } else {
        window.MV.accesstoken = data
        window.MV.root.postComment(window.MV.root, window.MV.root.postComment.callback)
        window.MV.root.alert.hide()
      }
    },
    error: function (status, data) {
      window.MV.root.error(status, data)
    }
  })
}
getrefreshtoken()
`
export default captcha