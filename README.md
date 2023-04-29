# ip-filter
使用lua实现的简单ip匹配

通过设置的模式串，检查ip是否符合改模式串，
支持的匹配包括纯ip，子网掩码和网络段
网络段支持通配符：192.168.201.* 和 通过'-'指定的范围：192.168.100-255.192
在同一段内*或-只能有一种，如192.168.100-*.102是非法的，
同一个模式的不同段可以有多种，如192.168.100-255.*是合法的

`test_ip-filter.lua`包含了使用方式以及几个测试用例。

## 依赖库
luabitop