# ohhho kernel

[![State-of-the-art Shitcode](https://img.shields.io/static/v1?label=State-of-the-art&message=Shitcode&color=7B5804)](https://github.com/trekhleb/state-of-the-art-shitcode)
![](https://img.shields.io/npm/v/ohhho?color=critical&logo=npm&style=flat-square)
![npm bundle size (scoped)](https://img.shields.io/bundlephobia/minzip/ohhho?style=flat-square&label=size)
![license](https://img.shields.io/github/license/MHuiG/ohhho)

*****

基于 CloudFlareWorker 和 CloudFlareKV 技术的评论系统内核实验项目。

******

# About

本项目是内核项目，故我们只保留基础评论功能。

我们拒绝了以下功能请求：

- 任何花里胡哨的功能
- 第三方数据接口
- 主题支持（永远没有）
- 评论管理系统
- 任何移除后基础评论仍然正常的功能
- 本项目文档（垃圾代码书写准则）

## Releases

最终生成物：

https://cdn.jsdelivr.net/npm/ohhho@0.0.4/dist/ohhho.min.js

https://cdn.jsdelivr.net/npm/ohhho@0.0.4/worker/dist/worker.js

签名文件：

https://cdn.jsdelivr.net/npm/ohhho@0.0.4/dist/ohhho.min.js.sig

https://cdn.jsdelivr.net/npm/ohhho@0.0.4/worker/dist/worker.js.sig



# 参数和指标

- 前端 JS 脚本共计一个（ohhho.min.js） 文件大小为 74.35 KB，gzip 压缩后为 22.3 KB。
- CloudFlareWorker 脚本共计一个（worker.js）。
- 系统关键请求共计3个。
- 中国地区使用 CloudFlareAnycast 技术和 DNSPOD 智能解析技术 以及 优选 CloudFlare节点 IP 负载均衡的方法，系统关键请求时间可在 100-300ms 左右。

# 安全策略

## 检测大文本攻击

文本长度大于1000000，请求将返回"那太大了"

## Cloudflare API 防火墙规则

环境变量：

`AUTHEMAIL`：  X-Auth-Email

`AUTHKEY` ： X-Auth-Key

`ZONEID` ： zone_identifier

存储记录15分钟内原始客户端（访问者）IP 地址、代理服务器 IP 地址、IP 地理位置（Cloudflare需开启 IP 地理位置）

15分钟内发送评论超过30条，访问者IP将被永久封禁。

Cloudflare 如何处理 HTTP 请求标头：

https://support.cloudflare.com/hc/zh-cn/articles/200170986

Cloudflare  防火墙 API文档：

 https://api.cloudflare.com/#firewall-rules-properties

 https://developers.cloudflare.com/firewall/api

  https://developers.cloudflare.com/firewall/cf-firewall-rules

# API

## 批准状态

评论数据 `approval `字段为 `false`则不会向前端发送展示数据。

## 目标API地址

环境变量：`APIPATH`

当前评论数据已完成存储后，向目标API地址发送包含当前评论数据的POST请求，供外部程序实现通知功能、垃圾评论检测等。

# 如何使用

目前代码处于可用或不可用状态，不提供任何担保。

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
