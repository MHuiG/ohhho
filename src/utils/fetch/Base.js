import ajax from '../plugins/ajax'
import Bean from './Bean'
import getScript from '../plugins/getScript'
function FetchBase (root) {
  const url = `${root.conf.serverURL}/comment`
  root.fetchCount = (root) => {
    ajax({
      url: url,
      type: 'GET',
      data: {
        type: 'count',
        path: root.conf.path
      },
      success: function (data) {
        root.el.querySelector('.count').innerHTML = data
      },
      error: root.error
    })
  }
  root.fetchTotalPages = (root, callback) => {
    ajax({
      url: url,
      type: 'GET',
      data: {
        type: 'totalPages',
        path: root.conf.path,
        pageSize: root.conf.pageSize
      },
      success: function (data) {
        callback(data)
      },
      error: root.error
    })
  }
  root.fetchParentList = (root, pageNum, callback) => {
    ajax({
      url: url,
      type: 'GET',
      data: {
        path: root.conf.path,
        pageSize: root.conf.pageSize,
        page: pageNum
      },
      success: function (data) {
        window.MV.PageData = data
        const item = new Bean()
        window.MV.PageDataList = item.beanList(data)
        callback(window.MV.PageDataList)
      },
      error: root.error
    })
  }
  root.fetchNextList = (root, id, callback) => {
    const list = []
    const data = window.MV.PageDataList
    for (let i = 0; i < data.length; i++) {
      if (data[i].children) {
        for (let j = 0; j < data[i].children.length; j++) {
          if (id == data[i].children[j].rid) {
            list.push(data[i].children[j])
          }
        }
      }
    }
    callback(list)
  }
  root.fetchNextCount = (root, id, showMore) => {
    const list = []
    const data = window.MV.PageDataList
    for (let i = 0; i < data.length; i++) {
      if (data[i].children) {
        for (let j = 0; j < data[i].children.length; j++) {
          if (id == data[i].children[j].rid) {
            list.push(data[i].children[j])
          }
        }
      }
    }
    if (list.length > 0) {
      showMore(1) // 显示加载更多
    }
  }
  root.postComment = (root, callback) => {
    root.postComment.callback = callback
    const item = new Bean()
    for (const i in root.C) {
      if (root.C.hasOwnProperty(i)) {
        let _v = root.C[i]
        if (i === 'at') { _v = _v.substr(1) }
        item.set(i, _v)
      }
    }
    let data = Object.create(null)
    data = {
      comment: item.comment,
      link: item.link,
      mail: item.mail,
      nick: item.nick,
      ua: item.ua,
      url: item.url,
      at: item.at,
      accesstoken: window.MV.accesstoken
    }
    if (data.at) {
      const parentNode = JSON.parse(window.atob(document.querySelector('#comment-' + item.rid + ' .comment-item').textContent))
      if (parentNode.pid) {
        data.pid = parentNode.pid
      } else {
        data.pid = parentNode.id
      }
      data.rid = parentNode.id
    }
    console.log(data) // test
    ajax({
      url: url,
      type: 'POST',
      data: data,
      success: function (data) {
        if (data.comment) {
          const item = new Bean()
          item.create(data)
          callback(item)
        } else if (data.code) {
          if (data.code == 601 || data.code == 602 || data.code == 603 || data.code == 604 || data.code == 605 || data.code == 607 || data.code == 608) {
            getScript(`${root.conf.serverURL}/ChallengeCaptcha`)
          } else {
            root.error(data.code, data)
          }
        } else {
          root.error(12138, data)
        }
      },
      error: function (status, data) {
        root.error(status, data)
      }
    })
  }
}

module.exports = FetchBase
