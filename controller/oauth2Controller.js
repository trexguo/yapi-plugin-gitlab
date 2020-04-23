const baseController = require('controllers/base.js');
const yapi = require('yapi.js');
const http = require('http');
const https = require('https');	// 添加 https 依赖
const fs = require('fs');	// 用于证书文件读取

class oauth2Controller {
    constructor(ctx){
        this.ctx = ctx;
    }

    async init(ctx) {
        this.$auth = true;
    }

    /**
     * oauth2 回调
     * @param ctx
     * @returns {Promise<void>}
     */
    async oauth2Callback(ctx) {
        try {
            // 获取code和state
            let oauthcode = ctx.request.query.code;
            if (!oauthcode) {
                return (ctx.body = yapi.commons.resReturn(null, 400, 'code不能为空'));
            }
            let ops = this.getOptions();
            // 通过code获取token
            let tokenpath = ops.tokenPath + '?client_id=' + ops.appId + '&client_secret='
                + ops.appSecret + '&code=' + oauthcode + "&grant_type=authorization_code&redirect_uri=" + encodeURIComponent(ops.redirectUri);
            let tokenResult = await this.requestInfo(ops, tokenpath, 'POST').then(function(res) {
                let jsonRes = JSON.parse(res);
                ctx.redirect('/api/user/login_by_token?token=' + jsonRes.access_token);
            }).catch(function(rej) {
                return {
                    status_code: rej.statuscode,
                    message: rej.statusMessage
                };
            });
            return ctx.body = yapi.commons.resReturn(tokenResult, 401, "授权失败");
        } catch (err) {
            ctx.body = yapi.commons.resReturn(null, 400, err.message);
        }
    }

    getOptions(){
        for (let i = 0; i < yapi.WEBCONFIG.plugins.length; i++) {
            if (yapi.WEBCONFIG.plugins[i].name === 'gitlab') {
                return yapi.WEBCONFIG.plugins[i].options;
            }
        }
        return null;
    }

    requestInfo(ops, path, method) {
        return new Promise((resolve, reject) => {
            let req = '';

            let client = http;	// 默认为 http 请求
            let options = {
                method: method
            };
            if (ops.host.indexOf('https') === 0) {	// 如果 host 以 https 开头
                client = https;	// 将连接设置为 https
     
                // gitlab 证书是自己生成的不获取证书文件会报 UNABLE_TO_VERIFY_LEAF_SIGNATURE 错误
                // 这个错误可以通过两种方式解决（任选一种即可）：
                // 1）options.rejectUnauthorized 设置成 false
                // 2）将 ssl 的根证书文件赋值给 options.ca
                options.ca = fs.readFileSync(ops.ca_path);
            }
            let http_client = client.request(ops.host + path,
                {
                    method: method
                },
                function(res) {
                    res.on('error', function(err) {
                        reject(err);
                    });
                    res.setEncoding('utf8');
                    if (res.statusCode != 200) {
                        reject({statuscode: res.statusCode, statusMessage: res.statusMessage});
                    } else {
                        res.on('data', function(chunk) {
                            req += chunk;
                        });
                        res.on('end', function() {
                            resolve(req);
                        });
                    }
                }
            );
            http_client.on('error', (e) => {
                reject({message: 'request error'});
            });
            http_client.end();
        });
    }
}

module.exports = oauth2Controller;
