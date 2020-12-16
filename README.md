使用golang基于libpcap写的一个dns流量分析程序

# DNS流量分析程序

本程序从指定网卡抓取DNS查询报文，进行报文分析得到clientIP、query-name字段，输出到指定syslog地址
输出格式如  {"clientip": "192.168.51.15","queryname":"x0cecoeie.co.localdomain"}
支持IPv4 IPv6网络，仅抓取UDP53，不支持TCP报文sniff
适配系统x86 centos7.x

一、部署
    依赖于libpcap 直接yum/apt安装即可无特殊版本要求
    二进制执行程序上传到系统目录

二、启动
    命令行前台启动，如需后台则nohup或者其他方式即可
    命令行参数：
           -address   指定syslog地址
           -n         制定网卡名字
           -h         参数说明

三、执行程序：dnsscan

四、测试数据：
    使用tcpreplay对DNS查询重放，8核配置下 2MB DNS查询流量 ～= 20Gbit全域流量的DNS查询量
