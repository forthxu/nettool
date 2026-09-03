# static/

这个目录整个被 `//go:embed static/*` 打进二进制，运行时不读磁盘。

## tailwind-3.4.17.js

Tailwind CSS 的浏览器运行时（Play CDN 构建），MIT 协议，原样取自
<https://cdn.tailwindcss.com/3.4.17>。

**为什么不直接外链 CDN：** 那样每打开一次管理后台，管理员浏览器都会向第三方发一次
请求，把 IP、User-Agent、Referer 带出去；内网和离线环境下界面还会整个掉样式，
也和「单文件二进制、无外部运行时依赖」这个说法自相矛盾。

**升级：**

```sh
curl -sSL -o static/tailwind-3.4.17.js https://cdn.tailwindcss.com/3.4.17
```

换版本时记得同步改文件名和 `index.html` 里的 `<script src>`。
