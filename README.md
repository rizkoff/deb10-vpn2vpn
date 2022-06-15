
инструкция по предоставлению доступа через vpn сервер ресурсов, полученных через клиентское vpn-подключение


 - получаем временный логин в ibm cloud (k8s-as-as-Service), Сергей предоставляет пароль, нужно успеть подключиться за 5 минут, после этого логин работает 1 день
`ibmcloud login -a https://cloud.ibm.com -u passcode -p XXXXXXXXXX`

 - настраиваем локальное окружение на удаленный k8s-aaS. Кластер может подсказать Сергей
`ibmcloud ks cluster config --cluster cajdat3f0avmh0uidcsg`

 - или вот эта команда
`kubectl config get-contexts`


`kubectl create ns vpn-ns`
`kubectl apply -f pod.vpn2vpn.yaml`
`kubectl apply -f svc.vpn-svc.yaml`
`kubectl exec -it -n vpn-ns pod/vpn2vpn -- bash`

 - зайдя в баш, выполняем шаги статьи (только с 1 по 8й) 
https://www.rosehosting.com/blog/how-to-set-up-an-openvpn-server-on-debian-10/

 - шаги

`apt update && apt -y upgrade`
`apt install wget openvpn iptables procps screen vim -y`


`wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz`
`tar -xvzf EasyRSA-3.0.8.tgz`
`cp -r EasyRSA-3.0.8 /etc/openvpn/easy-rsa`

`cd /etc/openvpn/easy-rsa`
 - файл vars (создаем) может выглядеть так:
cat vars <<<<<<
set_var EASYRSA                 "$PWD"
set_var EASYRSA_PKI             "$EASYRSA/pki"
set_var EASYRSA_DN              "cn_only"
set_var EASYRSA_REQ_COUNTRY     "USA"
set_var EASYRSA_REQ_PROVINCE    "Newyork"
set_var EASYRSA_REQ_CITY        "Newyork"
set_var EASYRSA_REQ_ORG         "AFL4env CERTIFICATE AUTHORITY"
set_var EASYRSA_REQ_EMAIL    "admin@afl4env.com"
set_var EASYRSA_REQ_OU          "AFL4env CA"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            rsa
set_var EASYRSA_CA_EXPIRE    7500
set_var EASYRSA_CERT_EXPIRE     36500
set_var EASYRSA_NS_SUPPORT    "no"
set_var EASYRSA_NS_COMMENT    "AFL4env CERTIFICATE AUTHORITY"
set_var EASYRSA_EXT_DIR         "$EASYRSA/x509-types"
set_var EASYRSA_SSL_CONF        "$EASYRSA/openssl-easyrsa.cnf"
set_var EASYRSA_DIGEST          "sha256"
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


`./easyrsa init-pki`
`./easyrsa build-ca nopass`
 - пример ввода:
>>> [Easy-RSA CA]:ALF4env

`./easyrsa gen-req vpnserver nopass`
`./easyrsa sign-req server vpnserver`
`./easyrsa gen-dh`


'''
cp pki/ca.crt /etc/openvpn/server/
cp pki/dh.pem /etc/openvpn/server/
cp pki/private/vpnserver.key /etc/openvpn/server/
cp pki/issued/vpnserver.crt /etc/openvpn/server/
'''

`./easyrsa gen-req vpnclient nopass`
`./easyrsa sign-req client vpnclient`

'''
cp pki/ca.crt /etc/openvpn/client/
cp pki/issued/vpnclient.crt /etc/openvpn/client/
cp pki/private/vpnclient.key /etc/openvpn/client/
'''



`cat /etc/openvpn/server.conf`
port 443
proto tcp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/vpnserver.crt
key /etc/openvpn/server/vpnserver.key
dh /etc/openvpn/server/dh.pem
server 10.8.0.0 255.255.255.0
#push "redirect-gateway def1"

push "route 172.17.0.0 255.255.0.0"
topology subnet

#push "dhcp-option DNS 208.67.222.222"
#push "dhcp-option DNS 208.67.220.220"
duplicate-cn
cipher AES-256-CBC
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
auth SHA512
auth-nocache
keepalive 20 60
persist-key
persist-tun
#compress lz4
daemon
user nobody
group nogroup
log-append /var/log/openvpn.log
verb 3
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

 - форвардинг 
`sysctl net.ipv4.ip_forward=1`
`sysctl -p`

 - старт vpn сервера
`service openvpn  start`

 - старт vpn клиента
`openconnect 195.218.189.34 -u sschastlyvenko -b`
 - предоставляем пароль акаунта КЦ sschastlyvenko `Password: 1hlha3cx`
 - т.к. подключение к КЦ произошло после старта vpn сервера, tun0,tun1 представляют соотв-но vpn-сервер и vpn-клиент:

 - пример выполнения `ip -br a`
'''
ip -br a
lo               UNKNOWN        127.0.0.1/8 ::1/128 
tunl0@NONE       DOWN           
eth0@if33        UP             172.30.205.89/32 fe80::b47b:11ff:feaa:1eff/64 
wg0              UNKNOWN        192.168.10.1/24 
tun0             UNKNOWN        10.8.0.1/24 fe80::1176:25bd:fa64:7571/64 
tun1             UNKNOWN        172.17.211.191/32 fe80::b2aa:a500:6c92:3a21/64 
'''
 - запоминаем ip соотв-щий tun1: 172.17.211.191 - в нашем примере

`iptables -t nat -A PREROUTING -s 172.17.206.16/28 -d 172.17.211.191/32 -i tun0 -j DNAT --to-destination 10.8.0.2`
`iptables -t nat -A POSTROUTING -o tun1 -j MASQUERADE`
 - 10.8.0.2 - это единственный клиент нашего vpn-2-vpn решения. строчка iptables посвящена ему



`iptables -S; echo; iptables -S -t nat`
'''
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -s 172.17.206.16/28 -d 172.17.211.191/32 -i tun0 -j DNAT --to-destination 10.8.0.2 <<<<<< Schastlivenko
-A POSTROUTING -o tun1 -j MASQUERADE
'''

`kubectl get svc -n vpn-ns `
'''
NAME                TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)           AGE
vpn-svc             NodePort       172.21.170.163   <none>        443:32401/TCP     14d
'''

`kubectl get svc -n vpn-ns vpn-svc -o yaml`
'''
apiVersion: v1
kind: Service
metadata:
  labels:
    app: debian
  name: vpn-svc
  namespace: vpn-ns
spec:
  externalTrafficPolicy: Cluster
  internalTrafficPolicy: Cluster
  ports:
  - name: http
    nodePort: 32401
    port: 443
    protocol: TCP
    targetPort: 443
  selector:
    app: debian
  sessionAffinity: None
  type: NodePort
'''

`kubectl get node -o wide`
'''
NAME            STATUS   ROLES    AGE   VERSION       INTERNAL-IP     EXTERNAL-IP       OS-IMAGE             KERNEL-VERSION       CONTAINER-RUNTIME
10.144.214.83   Ready    <none>   28d   v1.22.9+IKS   10.144.214.83   159.122.175.141   Ubuntu 18.04.6 LTS   4.15.0-176-generic   containerd://1.5.11
'''



клиент получает конфиг файл:

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
client
proto tcp
remote 159.122.175.141                                <<<<<<<<<<<<<<<<<<<<<<<<< EXTERNAL-IP из вывода `kubectl get node -o wide`
port 32401
dev tun
nobind
#route 172.17.0.0 255.255.0.0 10.8.0.1                <<<<<<<<<<<<<<<<<<<<<<<<< закомментировано: т.к. роутинг на стороне сервера
#redirect-gateway def1

key-direction 1

<ca>
-----BEGIN CERTIFICATE-----
... содержимое файла /etc/openvpn/server.conf на поде  <<<<<<<<<<<<<<<<<<<<<<<<
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
... содержимое файла /etc/openvpn/client/vpnclient.crt на поде <<<<<<<<<<<<<<<<
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
... содержимое файла /etc/openvpn/client/vpnclient.key на поде <<<<<<<<<<<<<<<<
-----END PRIVATE KEY-----
</key>
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

 - файлы можно забирать командой `kubectl cp` - на примере файла ca.crt:
`kubectl cp vpn-ns/vpn2vpn:/etc/openvpn/server/ca.crt ./ca.crt`
или копировать контент с экрана из bash пода
`cat /etc/openvpn/server/ca.crt`

