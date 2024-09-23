## 分析过程
当前集客网关X86版本：V3.1 Build2021111900 
下载地址：http://file.cnrouter.com/index.php/Index/apbeta.html  

在https://github.com/xz0609/JiKe_GateWay_AC_HA 的基础上修复了python版本升级后无法使用js2py的问题，GPT重构后的代码，使用hashlib替代js2py进行密码加密


## 插件
github地址： https://github.com/MagicStarTrace/JiKe_GateWay_AC_HA


## secrets.yaml 新增以下配置项
```python
jike_gateway_ac_host:  192.168.1.100   # 集客网关AC的IP地址示例
jike_gateway_ac_username: admin        # 用户名示例
jike_gateway_ac_password: admin        # 密  码示例
```

## HA的configuration.yaml或者packages/新增一个yaml文件添加以下配置项
```python
device_tracker:
  - platform: jike_gateway_ac
    host: !secret jike_gateway_ac_host            # 必填项，集客网关AC的IP地址
    username: !secret jike_gateway_ac_username    # 必填项，集客网关AC的登录账号
    password: !secret jike_gateway_ac_password    # 必填项，集客网关AC的登录密码
    include:
      - K2T                                       # 可选项，值为AP的设备名称，用于过滤AP
      - AP250MD

    # latitude: !secret home_latitude
    # longitude: !secret home_longitude

    consider_home: 30                             #设备离线延时
    interval_seconds: 30                          #扫描间隔时间
    new_device_defaults:
      track_new_devices: true
```

## 插件使用说明
将jike_gateway_ac文件夹放到HA的config/custom_components/目录下，并按以上的yaml配置后，重启HA就可以了
![截图](https://raw.githubusercontent.com/MagicStarTrace/JiKe_GateWay_AC_HA/refs/heads/master/ScreenshotOfHALog.jpg)
![截图](https://raw.githubusercontent.com/MagicStarTrace/JiKe_GateWay_AC_HA/refs/heads/master/ScreenshotOfHaEntity.jpg)

