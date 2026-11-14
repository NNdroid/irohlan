# 示例配置

每个文件都是对应子命令 `--config` 的**只读输入**。键名规则(历史长参数的
kebab-case 形式)、每个键的语义与默认值见主 [README](../README.md) 的
「配置文件」一节;未知键直接报错,不会静默忽略。

| 文件 | 用于 | 说明 |
|---|---|---|
| [`create.example.json`](create.example.json) | `irohlan create --config` | 最小可用创建者配置:子网、钉住的 IPv6 前缀、设备名、MTU、metrics 端口。**故意不写 `secret`** —— 创建者会自动生成并打印 |
| [`join.example.json`](join.example.json) | `irohlan join <ticket> --config` | 与 create 示例**成对**:口令换成创建者打印的那个,固定虚拟 IPv4 + 配对的 IPv6(host index 7) |
| [`run.example.json`](run.example.json) | `irohlan run --config` | `run` 的键都是覆盖项:这里只临时关掉持久化的中继上限,其余沿用 `network.json` |
| [`bench-creator.json`](bench-creator.json) | CI 与本地吞吐测试的创建者 | 隔离网络形态:无中继、无 mDNS、flood 总线、IPv4 单栈、MTU 1400。被 [`.github/workflows/test.yml`](../.github/workflows/test.yml) 直接引用 |
| [`bench-joiner.json`](bench-joiner.json) | 同上,加入方 | 与 bench-creator **共用口令**;`ip` 钉在 `10.13.37.2`。creator 关了 IPv6,这里不得带 `ip6` |

`bench-*` 两个文件里的 `secret` 只用于测试拓扑(仓库是公开的,请不要把它当
真实口令复用)。弱网(netem)矩阵测试见 [`bench/`](../bench/),它按 profile
自行生成配置;`test.yml` 则原样引用这里的两个静态文件,保证「示例能直接跑通」
这件事本身被 CI 守着。
