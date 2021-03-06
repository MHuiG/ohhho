# ohhho kernel

[![State-of-the-art Shitcode](https://img.shields.io/static/v1?label=State-of-the-art&message=Shitcode&color=7B5804)](https://github.com/trekhleb/state-of-the-art-shitcode)
![](https://img.shields.io/npm/v/ohhho?color=critical&logo=npm&style=flat-square)
![npm bundle size (scoped)](https://img.shields.io/bundlephobia/minzip/ohhho?style=flat-square&label=size)
![license](https://img.shields.io/github/license/MHuiG/ohhho)

*****

基于 CloudFlareWorker 和 CloudFlareKV/IPFS 技术的评论系统内核实验项目。

******

# About

本项目是实验项目，正在进行一次前所未有的实验。

本内核用于论证使用Cloudflare Workers构建无服务器应用程序并部署到Cloudflare的边缘网络；使用Cloudflare Workers KV全球分布式键值存储构建高度动态API；使用IPFS分布式文件系统实现去中心化分布式存储，搭建评论系统的可行性。

本项目是内核项目，故我们只保留基础评论功能。

我们拒绝了以下功能请求：

- 任何花里胡哨的功能
- 第三方数据接口
- 主题支持（永远没有）
- 评论管理系统
- 任何移除后基础评论仍然正常的功能
- 本项目文档（遵循垃圾代码书写准则，从一开始就要保持）

## Releases

最终生成物：

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/dist/ohhho.min.js

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/worker/dist/worker.js

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/dist/ohhh.o.min.js

签名文件：

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/dist/ohhho.min.js.sig

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/worker/dist/worker.js.sig

https://cdn.jsdelivr.net/npm/ohhho@0.0.23/dist/ohhh.o.min.js.sig

# 参数和指标

- 前端 JS 脚本完整版共计一个（ohhho.min.js） 文件大小约为 80 KB，gzip 压缩后约为 25 KB。
- 前端 JS 脚本无样式版共计一个（ohhh.o.min.js） 文件大小约为 45 KB。
- CloudFlareWorker 脚本共计一个（worker.js）。
- 系统关键请求共计 ~3个~ 1个(websocket)。
- ~~中国地区使用 CloudFlareAnycast 技术和 DNSPOD 智能解析技术 以及 优选 CloudFlare节点 IP 负载均衡的方法，~~ 系统关键请求时间可在 200-500ms 左右。


# 数据存储方案

## CloudFlareKV/IPFS 存储 (方案B)

IPFS 存储最终数据，无限存储空间，CloudFlareKV 存储 IPFS Hash，数据上传至 IPFS 永远不可删除

### 环境变量

`IPFSAPI` : IPFS API

由于 CloudFlareWorkers 神奇的 405 BUG ，请用其他方式自行搭建 IPFS API，基于 CloudFlareWorker 的 IPFS API 不可用

## 仅 IPFS 存储 (方案已废弃)

IPFS 存储最终数据，无限存储空间，数据上传至 IPFS 永远不可删除

！！封号警告！！  [Is it OK to use WAF as CloudFlareWorkerKV?](https://community.cloudflare.com/t/is-it-ok-to-use-waf-as-cloudflareworkerkv/254887)

![](https://cdn.jsdelivr.net/gh/MHuiG/imgbed@master/data/1616675804000.png)

## 仅 CloudFlareKV 存储 (方案已废弃)

1 GB 键值存储空间 | 100,000 每日键值读取 | 1000 每日键值写入/删除/清单 | 值的最大大小为25MB | 整个请求大小必须小于100兆字节

## CloudFlareKV/IPFS 存储 (方案A已废弃)

IPFS 存储最终数据，无限存储空间，CloudFlareKV 存储 IPFS Hash

# 数据加密方案

考虑到数据上传至 IPFS 的数据永远不可删除，于是对数据进行加密处理。数据加密处理时间约为90ms。

### 环境变量

`AESKEY` : 必须16位

战备策略，此功能策略在 ohhho kernel 处于数据安全危机下将被强行启用。

# 安全策略

## 检测大文本攻击

文本长度大于1000000，请求将返回"那太大了"

## Cloudflare API 防火墙规则

### 环境变量

`AUTHEMAIL`：  X-Auth-Email 【必填】

`AUTHKEY` ： X-Auth-Key 【必填】

`ZONEID` ： zone_identifier 【必填】

`ACCOUNTID` : account_id 【必填】

`WORKERNAME` : worker  script name 【必填】

`WORKERROUTE` : worker  route 【必填】 `xxx.xxx.com/*`

### 策略

#### 攻击频率 15/15min per ip

存储记录15分钟内原始客户端（访问者）IP 地址、代理服务器 IP 地址、IP 地理位置（Cloudflare需开启 IP 地理位置）

单IP15分钟内发送评论超过15条，访问者IP将被永久封禁且该ip超过 15/15min  的数据流不再存入。

#### 攻击频率 10/15min all ip

全部IP15分钟内发送评论超过10条，必须接受CAPTCHA(全自动区分计算机和人类的图灵测试).

环境变量：

`PRIVATEK` ： privatek 【必填】

`PRIVATEPASS` ： privatepass 【必填】

`CHECKRT` : true表示在有效期内AccessToken永久有效;false表示AccessToken在使用一次后就吊销

`CAPTCHAAPI` : 自定义 Captcha

示例：CAPTCHAAPI="https://test.workers.dev"

必须含有可用路径 /ChallengeCaptchaScript 和 /CheckChallengeCaptcha

/ChallengeCaptchaScript 需返回 自定义 Captcha JS 脚本，成功验证后 accesstoken 回调：

```
  window.MV.accesstoken=accesstoken
  window.MV.root.postComment(window.MV.root, window.MV.root.postComment.callback)
  window.MV.root.alert.hide()
```

验证失败回调：

```
  window.MV.root.el.querySelector('.vsubmit').removeAttribute('disabled-submit')
  window.MV.root.submitting.hide()
  window.MV.root.nodata.hide()
```

内核将向 /CheckChallengeCaptcha 发送 GET 请求 验证accesstoken，成功验证需返回字符串"OK"

错误代码需返回 capcode 从1开始编号

NOTE: 建议使用 workers.dev。

#### 攻击频率 12/15min all ip

全部IP15分钟内发送评论超过12条，启用强制等待策略，系统睡眠1分钟.

#### 攻击频率 20/15min all ip

全部IP15分钟内发送评论超过20条，Cloudflare 开启 Under Attack 模式且超过 20/15min all ip 的数据流不再存入；开启定时任务 UTC 21:00:00 恢复正常模式。

#### 攻击频率 30000/6h all ip all reqest all workers

六小时内KV流量请求超过30000，Cloudflare 开启 Under Attack 模式；开启定时任务 UTC 21:00:00 恢复正常模式。

六小时内KV流量请求超过35000，将删除本内核 Worker Script 路由。

请注意这是自我销毁行为。

### 文档

Cloudflare 如何处理 HTTP 请求标头：

https://support.cloudflare.com/hc/zh-cn/articles/200170986

Cloudflare  防火墙 API文档：

 https://api.cloudflare.com/#firewall-rules-properties

 https://developers.cloudflare.com/firewall/api

  https://developers.cloudflare.com/firewall/cf-firewall-rules

# 简易管理系统

环境变量：

`SITEPATH`

`USERNAME`

`PASSWORD`

`OHHHOPATH`

# API

## 配色方案

可使用 CSS 变量修改配色方案.

## 批准状态

评论数据 `approval `字段为 `false`则不会向前端发送展示数据。

## 目标API地址

环境变量：`APIPATH`

当前评论数据已完成存储后，向目标API地址发送包含当前评论数据的POST请求，供外部程序实现通知功能、垃圾评论检测等。

# KPI

KPI 即 Kernel API

```bash
npm i --save ohhho
```

安装后可以在项目中直接使用[ohhho/worker/kernel](https://github.com/MHuiG/ohhho/tree/master/worker/kernel)中封装后的方法

例如 kernel.cf.api.getFilters() 等,示例：

```js
import kernel from 'ohhho/worker/kernel'
......
    if (path.startsWith("/test-md")) {
        const s = urlObj.searchParams.get('s')
        return new Response(kernel.util.getMd(s), kernel.util.headers.js)
    }
......
```

# 如何使用

目前代码处于可用或不可用状态，不提供任何担保。

# 大事记

2021.04.23 内核首次完成 websocket 部署

2021.04.01 内核首次完成 Kernel API 封装

2021.03.25 内核部署 CloudFlareKV/IPFS 存储方案B,并废弃旧有数据存储方案

2021.03.23 内核首次实现完全 IPFS 存储，并移除旧有数据存储方案

2021.03.19 内核部署简易管理系统

2021.03.16 内核部署数据加密方案

2021.03.15 内核首次实现 CloudFlareKV/IPFS 存储方案

2021.03.14 内核完成第一版安全策略部署

2021.03.07 内核首次实现基于 CloudFlareKV 的存储方案

2021.03.06 内核发布第一个~不可用~版本

# 致谢

本内核前端使用了 MiniValine 的核心部分，在此特别感谢所有参与 MiniValine 开发的贡献者，感谢 MiniValine V5 版本之前的 56⭐ users ~~V4的仓库被我误删了~~，感谢 MiniValine V5 版本之后的所有 Star Users。

Thanks to [CloudFlare](https://www.cloudflare.com) for their support.

<img src="https://www.cloudflare.com/img/logo-web-badges/cf-logo-on-white-bg.svg" width="300">

# 许可

使用严格的 GPL-3.0 开源许可（GPL-3.0 Only）,这意味着我们拒绝使用任何 GPL-2.0 Only 开源许可的源代码，同时拒绝向遵循 GPL-2.0 Only 的开源库提供授权；所有根据 **ohhho kernel** 开发的程序若重新分发，则必须遵循**GPLv3 或者其以后版**协议并开源。

```
    ohhho kernel
    Copyright (C) 2021 MHuiG

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

```

## 授权链

[ohhho kernel](https://github.com/MHuiG/ohhho) [2021.3.7](https://github.com/MHuiG/ohhho/tree/f8896843ee3dfb5c0b4213a0f7a57fa96b4d10ee)-present [GPL-3.0 Only](https://github.com/MHuiG/ohhho/blob/master/LICENSE)

[MiniValine](https://github.com/MiniValine/MiniValine) [2020.3.10](https://github.com/MiniValine/MiniValine/tree/c572885421f5818b13931ba3023689897d41df16)-[2021](https://github.com/MiniValine/MiniValine/tree/e006726baf526478d890429b50c376b9e7c534a2) [GPLV3 or later](https://github.com/MiniValine/MiniValine/blob/e006726baf526478d890429b50c376b9e7c534a2/LICENSE)

[Valine-Ex](https://github.com/DesertsP/Valine) [2017.8.13](https://github.com/DesertsP/Valine/tree/80caa2600f4cf92b84ec1b9815077748dd16dcbf)-[2019.5.28](https://github.com/DesertsP/Valine/tree/71090fed6e336ffded7d3e56f0909c8443c2bf8a)  [GPL-2.0 Only](https://github.com/DesertsP/Valine/blob/71090fed6e336ffded7d3e56f0909c8443c2bf8a/LICENSE)

[Valine](https://github.com/xCss/Valine) [2017.8.3](https://github.com/xCss/Valine/tree/e1fb38559efa085866f531b473f4050001b97b83)-[2017.8.13](https://github.com/xCss/Valine/tree/cefd272eacdea665f20bc1eeeb18780984896eb2) [GPL-2.0 Only](https://github.com/xCss/Valine/blob/cefd272eacdea665f20bc1eeeb18780984896eb2/LICENSE)

向以上开源项目以及贡献者致敬！
