#!/bin/sh
export LANG=en_US.UTF-8
export uuid=${uuid:-''}
export port_hy2=${hypt:-''}
export port_vl_re=${vlpt:-''}

hostname=$(uname -a | awk '{print $2}')
op=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty_name | cut -d \" -f2)
[ -z "$(systemd-detect-virt 2>/dev/null)" ] && vi=$(virt-what 2>/dev/null) || vi=$(systemd-detect-virt 2>/dev/null)
case $(uname -m) in
aarch64) cpu=arm64;;
x86_64) cpu=amd64;;
*) echo "目前脚本不支持$(uname -m)架构" && exit
esac
mkdir -p "/app"

v4v6(){
v4=$(curl -s4m5 icanhazip.com -k)
v6=$(curl -s6m5 icanhazip.com -k)
}

insuuid(){
if [ -z "$uuid" ]; then
uuid=$("/app/sing-box" generate uuid)
fi
echo "$uuid" > "/app/uuid"
echo "UUID密码：$uuid"
}
installsb(){
echo
echo "=========启用Sing-box内核========="
if [ ! -e "/app/sing-box" ]; then
curl -Lo "/app/sing-box" -# --retry 2 https://github.com/yonggekkk/ArgoSB/releases/download/argosbx/sing-box-$cpu
chmod +x "/app/sing-box"
sbcore=$("/app/sing-box" version 2>/dev/null | awk '/version/{print $NF}')
echo "已安装Sing-box正式版内核：$sbcore"
fi
cat > "/app/sb.json" <<EOF
{
"log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
EOF
insuuid
openssl ecparam -genkey -name prime256v1 -out "/app/private.key" >/dev/null 2>&1
openssl req -new -x509 -days 36500 -key "/app/private.key" -out "/app/cert.pem" -subj "/CN=www.bing.com" >/dev/null 2>&1
hyp=hypt
if [ -n "$hyp" ]; then
hyp=hypt
if [ -z "$port_hy2" ]; then
port_hy2=$(shuf -i 10000-65535 -n 1)
fi
echo "$port_hy2" > "/app/port_hy2"
echo "Hysteria2端口：$port_hy2"
cat >> "/app/sb.json" <<EOF
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "listen": "::",
        "listen_port": ${port_hy2},
        "users": [
            {
                "password": "${uuid}"
            }
        ],
        "ignore_client_bandwidth":false,
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "/app/cert.pem",
            "key_path": "/app/private.key"
        }
    },
EOF
else
hyp=hyptargo
fi
tup=vlpt
if [ -n "$tup" ]; then
tup=vlpt
if [ -z "$port_vl_re" ]; then
port_vl_re=$(shuf -i 10000-65535 -n 1)
fi
echo "$port_vl_re" > "/app/port_vl_re"
echo "re端口：$port_vl_re"
cat >> "/app/sb.json" <<EOF
    {
      "type": "vless",   
      "tag": "vless-sb",
      "listen": "::",
      "listen_port": ${port_vl_re},
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
          "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.yahoo.com",
            "server_port": 443
          },
          "private_key": "oDARpk0geWF4KQsRjh9tV7BMwsuML7ypcv-_PSdEgHI",
          "short_id": ["a01f48bd"]
        }
      }
    },
        
EOF
else
tup=tuptargo
fi



}


xrsbout(){

if [ -e "/app/sing-box" ]; then
sed -i '${s/,\s*$//}' "/app/sb.json"
cat >> "/app/sb.json" <<EOF
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}

EOF
nohup "/app/sing-box" run -c "/app/sb.json" >/dev/null 2>&1 &
fi
}

killstart() {
    echo "  -> [killstart] 开始执行..."
    # --- 1. 精确地杀死目标进程 ---
    # 目标是 /app/sing-box，而不是旧的 /zjsb/
    local app_path="/app/sing-box"
    echo "  -> [killstart] 正在清理任何与 '$app_path' 相关的旧进程..."

    # 方法A: 使用 pgrep 和 kill，更高效
    # pgrep -f "$app_path" 找到所有命令行包含 /app/sing-box 的进程ID
    local pids_to_kill=$(pgrep -f "$app_path")
    if [ -n "$pids_to_kill" ]; then
        # 先尝试优雅关闭 (SIGTERM)
        kill -15 $pids_to_kill >/dev/null 2>&1
        sleep 1 # 等待进程响应
        
        # 检查是否还有残留，强制杀死 (SIGKILL)
        if pgrep -f "$app_path" >/dev/null; then
            echo "  -> [killstart] 优雅关闭失败，正在强制终止..."
            kill -9 $(pgrep -f "$app_path") >/dev/null 2>&1
        fi
        echo "  -> [killstart] 旧进程清理完毕。"
    else
        echo "  -> [killstart] 未找到需要清理的旧进程。"
    fi

    # --- 2. 检查并启动新进程 ---
    local config_path="/app/sb.json"
    
    # 检查可执行文件和配置文件是否存在
    if [ ! -x "$app_path" ]; then
        echo "  -> [killstart] 错误: sing-box 可执行文件 '$app_path' 不存在或没有执行权限！"
        return 1 # 返回错误码
    fi
    if [ ! -f "$config_path" ]; then
        echo "  -> [killstart] 错误: 配置文件 '$config_path' 不存在！"
        return 1 # 返回错误码
    fi

    echo "  -> [killstart] 正在启动新的 sing-box 进程..."
    # 使用 nohup 在后台启动，并将标准错误输出到日志文件，方便排查问题
    nohup "$app_path" run -c "$config_path" >/dev/null 2>&1 &
    
    # --- 3. 智能等待和验证 ---
    echo "  -> [killstart] 等待进程启动 (最多10秒)..."
    for i in 1 2 3 4 5 6 7 8 9 10
    do
        if pgrep -f "$app_path" >/dev/null; then
            echo "  -> [killstart] 成功！sing-box 进程已启动。"
            return 0 # 返回成功码
        fi
        echo "     ...等待中 ($i/10)"
        sleep 1
    done

    echo "  -> [killstart] 错误: 等待超时，sing-box 进程未能启动！"
    echo "  -> [killstart] 请检查日志文件获取详细信息: /app/sing-box.log"
    return 1 # 返回错误码
}


ins(){


installsb
xrsbout
xhp="xhptargo"; vlp="vlptargo"


echo '@reboot /bin/sh -c "nohup /app/sing-box run -c /app/sb.json >/dev/null 2>&1 &"' >> /tmp/crontab.tmp

crontab /tmp/crontab.tmp 2>/dev/null
rm /tmp/crontab.tmp
if pgrep -f "sing-box" > /dev/null
then
echo "ArgoSB脚本进程启动成功，安装完毕" && sleep 2
else
echo "ArgoSB脚本进程未启动，安装失败尝试重新启动"

if ! killstart; then
            echo "错误：重试启动 sing-box 失败，请手动检查。脚本退出。"
            exit 1
        fi
        # 如果 killstart 成功，脚本可以继续
        echo "重试启动成功"
    
fi

}

cip(){
ipbest(){
serip=$(curl -s4m5 icanhazip.com -k || curl -s6m5 icanhazip.com -k)
if echo "$serip" | grep -q ':'; then
server_ip="[$serip]"
echo "$server_ip" > "/app/server_ip.log"
else
server_ip="$serip"
echo "$server_ip" > "/app/server_ip.log"
fi
}
ipchange(){
v4v6
if [ -z "$v4" ]; then
vps_ipv4='无IPV4'
vps_ipv6="$v6"
elif [ -n "$v4" ] && [ -n "$v6" ]; then
vps_ipv4="$v4"
vps_ipv6="$v6"
else
vps_ipv4="$v4"
vps_ipv6='无IPV6'
fi
if echo "$v6" | grep -q '^2a09'; then
w6="【WARP】"
fi
if echo "$v4" | grep -q '^104.28'; then
w4="【WARP】"
fi
echo
echo "=========当前服务器本地IP情况========="
echo "本地IPV4地址：$vps_ipv4 $w4"
echo "本地IPV6地址：$vps_ipv6 $w6"
echo
sleep 2
if [ "$ipsw" = "4" ]; then
if [ -z "$v4" ]; then
ipbest
else
server_ip="$v4"
echo "$server_ip" > "/app/server_ip.log"
fi
elif [ "$ipsw" = "6" ]; then
if [ -z "$v6" ]; then
ipbest
else
server_ip="[$v6]"
echo "$server_ip" > "/app/server_ip.log"
fi
else
ipbest
fi
}
ipchange
uuid=$(cat "/app/uuid")
server_ip=$(cat "/app/server_ip.log")
echo "*********************************************************"
echo "*********************************************************"
echo "ArgoSB脚本输出节点配置如下："
echo

if [ -f "/app/port_vl_re" ]; then
echo "💣【 vless-reality-vision 】节点信息如下："
port_vl_re=$(cat "/app/port_vl_re")
vl_link="vless://$uuid@$server_ip:$port_vl_re?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=oDARpk0geWF4KQsRjh9tV7BMwsuML7ypcv-_PSdEgHI&sid=a01f48bd&type=tcp&headerType=none#${sxname}vl-reality-vision-$hostname"
echo "$vl_link" >> "/app/jh.txt"
echo "$vl_link"
echo
fi


if [ -f "/app/port_hy2" ]; then
echo "💣【 Hysteria2 】节点信息如下："
port_hy2=$(cat "/app/port_hy2")
hy2_link="hysteria2://$uuid@$server_ip:$port_hy2?security=tls&alpn=h3&insecure=1&sni=www.bing.com#${sxname}hy2-$hostname"
echo "$hy2_link" >> "/app/jh.txt"
echo "$hy2_link"
echo
fi


echo "---------------------------------------------------------"

echo "---------------------------------------------------------"

}
if pgrep -f "sing-box" > /dev/null
then
    # 如果 pgrep 找到了进程 (退出码为 0)，则执行这里的代码
    echo "sing-box 正在运行，退出脚本。"
    exit 0
else
    # 如果 pgrep 没找到进程 (退出码非 0)，则执行这里的代码
    echo "sing-box 未运行，开始执行安装程序..."
    echo "VPS系统：$op"
    echo "CPU架构：$cpu"
    echo "ArgoSB脚本未安装，开始安装…………" && sleep 2
    setenforce 0 >/dev/null 2>&1
    iptables -P INPUT ACCEPT >/dev/null 2>&1
    iptables -P FORWARD ACCEPT >/dev/null 2>&1
    iptables -P OUTPUT ACCEPT >/dev/null 2>&1
    iptables -F >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1
    ins
    cip
    echo "################################################"
    echo "## 安装脚本执行完毕，sing-box 已在后台运行。 ##"
    echo "## 脚本现在将正常退出。                   ##"
    echo "################################################"
    exit 0
fi









