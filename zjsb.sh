#!/bin/sh
export LANG=en_US.UTF-8
export uuid=${uuid:-''}
export port_hy2=${hypt:-''}
export port_vl_re=${vlpt:-''}
export TOKEN=$TOKEN
export ZONE_ID=$ZONE_ID
export RECORD_ID=$RECORD_ID
export NAME=$NAME




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
curl -Lo "/app/sing-box" -# --retry 2 https://github.com/xiezeng92/zjsb/releases/download/tar/sing-box-$cpu
chmod +x "/app/sing-box"
sbcore=$("/app/sing-box" version 2>/dev/null | awk '/version/{print $NF}')
echo "已安装Sing-box正式版内核：$sbcore"
fi
cat > "/app/sb.json" <<EOF
{
"log": {
    "level": "fatal"
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

fi
}




ins(){


installsb
xrsbout
xhp="xhptargo"; vlp="vlptargo"

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

    # 如果 pgrep 没找到进程 (退出码非 0)，则执行这里的代码
    echo "sing-box 未运行，开始执行安装程序..."
    echo "VPS系统：$op"
    echo "CPU架构：$cpu"
    echo "ArgoSB脚本未安装，开始安装…………" && sleep 2
    ins
    cip
    echo "################################################"
    echo "## 安装脚本执行完毕，sing-box 已在后台运行。 ##"
    echo "## 脚本现在将正常退出。                   ##"
    echo "################################################"
    if [ -n "$TOKEN" ] && [ -n "$ZONE_ID" ] && [ -n "$RECORD_ID" ] && [ -n "$NAME" ]; then
    echo "==> 检测到 Cloudflare 环境变量，准备更新 DNS 记录..."
    IP=$(curl -s4 ifconfig.me)
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"${NAME}\",\"content\":\"${IP}\",\"ttl\":1,\"proxied\":false}" | grep '"success":true' && echo "DNS ok" || echo "DNS no ok"
    else
    echo "==> 未提供完整的 Cloudflare 环境变量，跳过 DNS 更新。"
    fi
exec "$@"
