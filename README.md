# SuperEdge金丝雀（v1.9.3）

VLESS over WebSocket 的 Cloudflare Workers 单文件代理。对外是一套可正常浏览的 SaaS 门面站点，对内提供两个私有面板用于生成节点链接。

## 目录结构

```
src/
  config.js      全局配置、三档 profile、启动期校验
  core.js        协议层与出站层（SOCKS5 / HTTP 隧道 / 竞速）
  session.js     缓冲合包、下行泵、单连接状态机
  i18n.js        门面站点多语言文案
  web.js         门面站点页面、robots、sitemap、favicon、404、通用登录页
  api.js         门面 API 的 JSON 响应
  2panel.js      新面板页面拼装
  index.js       入口路由、策略解析、面板鉴权、旧面板渲染
  2panel/        新面板客户端资源（2panel.html / .css / .js）
scripts/
  build.mjs      构建入口，输出 dist/_worker.js
  local-sim.mjs  本地模拟器：页面/API 用例 + WebSocket 回显链路
dist/_worker.js  构建产物（wrangler.toml 的 main 指向此文件）
```

根目录的 `SuperEdge金丝雀_Preview_v1.9.2.js` 是项目原生单文件版本，保留作为参考基线，不参与当前构建。

## 常用命令

```bash
npm install
npm run build     # 生成 dist/_worker.js，并在终端打印本次凭证
npm run dev       # 构建后启动 wrangler dev
npm run deploy    # 构建后发布到 Cloudflare
node scripts/local-sim.mjs   # 本地模拟器，默认 http://127.0.0.1:8787
```

`dev` / `deploy` 调用 `wrangler`，但它未写入 devDependencies。干净环境请先执行 `npm install -D wrangler`，或改用 `npx wrangler dev` / `npx wrangler deploy`。

本地模拟器可用环境变量 `PORT` 覆盖端口，启动后访问 `/sim` 查看数据流向监控台。

## 凭证

`scripts/build.mjs` 每次构建都会随机生成 UUID、Panel Key、Panel PIN，并注入产物，不写回源码。

- 三者只打印在构建终端，请及时保存。
- 重新构建会换新凭证，已分发的节点链接和面板入口会全部失效。
- `dist/_worker.js` 内含凭证，按机密文件对待，不要提交或外发。

## 入口

```
旧面板：/?panel=<Panel Key>
新面板：/?2panel=<Panel Key>
```

旧面板保持 v1.9.2 的解锁流程：入口页先显示 PIN 锁，节点UUID 以 AES-GCM 密文嵌入，输入管理员 PIN 后由浏览器解密并渲染面板，不经过 `/auth`。

新面板（v1.9.3）在未通过服务端校验时只返回门面风格的通用登录页，页面不含面板、节点、PIN、协议或版本信息。

- `POST /auth` 同时校验节点UUID 与管理员 PIN，通过后签发 12 小时 HttpOnly 会话 Cookie。
- 禁用 JavaScript 的表单提交同样可用：成功返回 303 跳回新面板入口，失败返回带错误提示的登录页。
- 新面板会话有效时才下发 HTML，节点UUID 明文随页面注入。
- 新面板内的锁定按钮或 15 分钟空闲会调用 `POST /auth/logout`，清 Cookie 后回到通用登录页。
- 同一 IP 单实例 10 分钟最多失败 60 次，正常登录与注销不计数；超出返回 429。

## 客户端 Path

```
纯直连       ?ed=2560
proxyip      ?ed=2560&ip=1.2.3.4:443
局部 SOCKS5  ?ed=2560&s5=<URL 编码后的 socks5://user:pass@host:port>
局部 HTTP    ?ed=2560&h=<URL 编码后的 http://user:pass@host:port>
全局 SOCKS5  ?ed=2560&g5=...
全局 HTTP    ?ed=2560&gh=...
传输档位     末尾追加 &ll=0 / &ll=1 / &ll=2（默认 ll=0）
```

## 面板术语

两套面板统一使用以下名称，改动文案时请沿用：

- 节点UUID：vless 链接中 `@` 之前的 UUID；新面板用它登录，旧面板解锁后用它生成链接。
- 管理员 PIN：旧面板解锁与新面板服务端校验共用，通用登录页上显示为「**访问密钥**」。
- 出站方式：纯直连 / proxyip / SOCKS5 / HTTP 等出站选择。
- 接入路径：`CFG.pathPrefix` 中的 WebSocket 路径。
- 传输档位：ll=0 均衡 / ll=1 低延迟 / ll=2 高速下载。

## 安全注意

- 二维码由第三方 `qr.tgds.eu.org` 生成，请求会把含节点UUID 的完整链接作为参数发出，仅在需要时点击生成。
- 新面板登录凭证只提交给服务端校验，页面不写入 localStorage；会话 Cookie 为 HttpOnly、SameSite=Lax，12 小时过期。旧面板的 PIN 仅在浏览器内用于解密节点UUID，可被离线暴力尝试。
- 门面站点不接入任何统计脚本。
- 修改 `src/` 后需要重新构建，`dist/` 不会自动同步。


## 📄 开源许可证 (License)

本项目基于 [Apache License 2.0](LICENSE) 协议开源。你可以自由使用、修改、分发本项目，但需保留原作者版权声明及开源许可证。
