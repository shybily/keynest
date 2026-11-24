# Keynest Mobile SDK

Keynest 移动端 SDK 由只读客户端组成，不提供周期轮询。

宿主应用负责冷启动和恢复前台时触发刷新；SDK负责请求去重、版本检查、解密、缓存回退和最小刷新间隔。

目录：

- [Android SDK](android/)
- [iOS SDK](ios/)
- [共享协议向量](shared/test-vectors/)
- [移动端配置选项](CONFIGURATION.md)
- [只读协议规范](openapi.yaml)
