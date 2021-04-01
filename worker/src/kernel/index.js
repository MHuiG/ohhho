import util from "./util";
import cf from "./cf";
import page from "./page";
import ipfs from "./ipfs";
import captcha from "./captcha";
import crypto from "./crypto";
import sec from "./sec";
import admin from "./admin";
let kernel= {
  util: util,
  cf: cf,
  page: page,
  ipfs: ipfs,
  captcha: captcha,
  crypto: crypto,
  sec: sec,
  admin: admin,
};
export default kernel