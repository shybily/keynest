# Mobile SDK 配置选项

移动端 SDK 是只读配置客户端。以下选项同时适用于 Android 和 iOS；平台实现应保持默认值与语义一致。

## 连接与凭据

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `baseURL` | `string` / `URL` | 无，必填 | Keynest 配置中心地址，例如 `https://config.example.internal`。生产环境必须使用 HTTPS，末尾斜杠会被 SDK 统一处理。 |
| `accessToken` | `string` | 无，必填 | 对应项目、环境和服务的只读访问令牌，通过 HTTP `Authorization: Bearer` 发送。不得硬编码到源码、公开资源或日志中。 |
| `privateKeyPEM` | `bytes` / `string` | 无，必填 | 服务私钥的 PEM 内容。用于 RSA-OAEP-SHA256 解密内容密钥。必须通过安全初始化流程导入；Android 使用 Keystore 保护，iOS 使用 Keychain 保护。 |

## 生命周期刷新

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `refreshOnLaunch` | `bool` | `true` | 应用冷启动后是否自动刷新。宿主应用应在启动初始化完成且处于前台时调用一次刷新。进程热启动不视为冷启动。 |
| `refreshOnAppActive` | `bool` | `true` | 应用恢复前台后是否刷新。Android 使用整个进程的 `ProcessLifecycleOwner`，iOS 使用单一 `didBecomeActive` 或 `sceneDidBecomeActive` 来源，避免重复触发。 |
| `foregroundOnly` | `bool` | `true` | 是否禁止应用在后台执行刷新。两端应取消或不发起后台请求；宿主切后台时可取消在途任务。 |
| `minimumForegroundInterval` | `duration` | `30s` | 应用连续或频繁进入前台时，两次网络刷新之间的最短间隔。小于间隔时使用缓存，不发起网络请求。手动刷新应绕过此限制。 |

`refreshOnLaunch` 和 `refreshOnAppActive` 是推荐的宿主集成开关，不代表 SDK 会自行监听任何生命周期；宿主必须显式注册 Android 或 iOS 生命周期回调。

## 缓存与离线行为

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `serveCacheImmediately` | `bool` | `true` | 是否在网络刷新前或刷新期间立即返回本地缓存。适合冷启动时先展示旧配置，再静默更新为最新版本。 |
| `fallbackToCacheOnUnavailable` | `bool` | `true` | 网络不可达或服务端返回 `408`、`429`、`5xx` 时，是否使用有效缓存。缓存不存在时返回中心不可用错误。 |
| `cacheEnabled` | `bool` | `true` | 是否启用加密信封缓存。缓存只保存服务端返回的 `Envelope` JSON，不保存解密后的明文、Token 或私钥。 |

缓存要求：

- 缓存键包含 `baseURL`、`project`、`environment`、`service`、渲染格式和私钥身份。
- 相同地址但私钥不同，不得复用旧缓存。
- 缓存解密失败、缓存格式损坏或缓存地址不匹配时，不得静默覆盖有效配置。
- 解密成功的新配置可覆盖旧缓存；解密失败不得覆盖旧缓存。
- 新版本低于缓存版本时应返回 `VersionConflict`，不得回退到较旧版本。
- 应用卸载或用户主动清除数据时，缓存应随应用存储一起清理。

## 网络与重试

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `requestTimeout` | `duration` | `10s` | 单次 HTTP 请求超时时间。超时不会清除缓存。 |
| `deduplicateRefreshRequests` | `bool` | `true` | 是否合并同一地址的并发刷新。冷启动和前台激活同时触发时只发送一个请求，其他调用共享同一任务结果。 |
| `retryCount` | `int` | `1` | 网络请求失败后的额外重试次数，不包含首次请求。不可重试的鉴权、地址或协议错误不应触发重试。 |
| `retryInterval` | `duration` | `1s` | 两次重试之间的固定间隔。首版可使用固定退避，不实现指数退避。 |

建议重试范围：

- 可重试：网络中断、超时、`408`、`429`、`5xx`。
- 不重试：`401`、`403`、`404`、地址校验失败、私钥无效、算法不支持、解密失败。
- `304 Not Modified` 不属于重试或错误。
- 应用进入后台时应取消正在执行的重试。

## 生命周期刷新流程

```text
应用冷启动
  ├─ 读取缓存
  ├─ 缓存存在且 serveCacheImmediately=true：立即返回缓存
  └─ refreshOnLaunch=true：在前台执行一次网络刷新

应用恢复前台
  └─ refreshOnAppActive=true
      ├─ 距离上次刷新达到 minimumForegroundInterval：执行刷新
      └─ 未达到间隔：复用缓存或当前配置，不发起请求

应用进入后台
  └─ foregroundOnly=true：取消刷新任务并停止重试
```

## 生命周期

Android 使用 `ProcessLifecycleOwner` 区分整个应用进入前台和后台；iOS 使用 `didBecomeActiveNotification` 或 `sceneDidBecomeActive`。

宿主应用只负责触发刷新，不负责轮询。

## 刷新去重

同一地址在最小刷新间隔内只允许一个网络请求。冷启动和前台激活同时触发时，共享同一个 `refresh` 任务。

## 缓存隔离

缓存键必须包含：

```text
baseURL
project
environment
service
suffix
public-key identity
```

切换私钥后不得复用旧密文缓存。
