#!/bin/bash

#获取工作路径
CURRENT_DIR=$(
	cd $(dirname $0)
	pwd
)
#读取token
token=$(cat $CURRENT_DIR/bb.json)
#设置默认Headers参数
Header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36"
Rererer=https://www.aliyundrive.com/
#刷新token并获取drive_id、access_token
response=$(curl https://auth.aliyundrive.com/v2/account/token -X POST -H "User-Agent:$Header" -H "Content-Type:application/json" -H "Rererer:$Rererer" -d '{"refresh_token":"'$token'", "grant_type": "refresh_token"}')
drive_id=$(echo "$response" | sed -n 's/.*"default_drive_id":"\([^"]*\).*/\1/p')
new_token=$(echo "$response" | sed -n 's/.*"refresh_token":"\([^"]*\).*/\1/p')
access_token=$(echo "$response" | sed -n 's/.*"access_token":"\([^"]*\).*/\1/p')
if [ -z "$new_token" ]; then
	echo "刷新Token失败"
	exit 1
fi
echo -n ${new_token} >$CURRENT_DIR/bb.json
echo -n "{
'use_internal_storage':false,
'token':'d2e9fbc8a5ab41f6b26cd52ec2405fa9',
'open_token':'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlN2JiYjUzMThhNjI0Mzg3YTk0ZjE4NzdlYmU2YTIxZiIsImF1ZCI6IjY0MWQ4NDRlNDI2ODQxZWE5MGNmNmYzZjkzM2UwYWY3IiwiZXhwIjoxNzIwNjEzNzA2LCJpYXQiOjE3MTI4Mzc3MDYsImp0aSI6IjVjODQzMmZjOGE4NTQ2NDliMDEwOTY2OGQyNjEzNmQ3In0.YDbBTTKFhYgc0EF3Xe7CJSS24lrLz-El0ZQCWyg7d7ILe16b-vCl39v6gLVeayw31X5i3feaKXDT4eoT4OHCdQ',
'thread_limit':32,
'is_vip':true,
'vip_thread_limit':0,
'vod_flags':'4kz|auto',
'quark_thread_limit':32,
'quark_is_vip':true,
'quark_vip_thread_limit':0,
'quark_flags':'4kz|auto',
'uc_thread_limit':0,
'uc_is_vip':false,
'uc_vip_thread_limit':0,
'uc_flags':'4kz|auto',
'thunder_thread_limit':2,
'thunder_is_vip':false,
'thunder_vip_thread_limit':2,
'thunder_flags':'4k|4kz|auto',
'aliproxy':'',
'aliproxy_url':'https://gitlab.com/kerkier/yhb/-/raw/main/lib/aliproxy.gz;md5=d68c23c1f2d7f95f79e337532e1513a1',
'proxy':'',
'open_api_url':'get|https://adrive.xdow.net/oauth/access_token',
'oauth_client_id':'641d844e426841ea90cf6f3f933e0af7',
'oauth_client_secret':'',
'oauth_auth_url':'',
'oauth_refresh_url':'',
'danmu':true,
'quark_danmu':true,
'quark_cookie':'__pus=c9d812947208e96d629bb48edb94457cAARymqA48yfktGNXsOhQvbpkH1rW4zhtSQO8iYV/9mwcC7Ng4qE905+fJS17EGseuw+OQzKQej/+rIt5rYQdaJJI',
'uc_cookie':'__pus=5d97726d369b78bfb20bacdff42f8697AATsNBRgW4a6Qu227UH/ZI9SYfsrkpNJCdzRe3x4/hXu+cL8M30SwHoDNvRE0ZQp84y0/2I295+0ZZ7ksRt2sweB;__puus=7dfa559672bf66a840a9e931ef7e765bAAQDy6Q2bpV/Fd8NRo28Pkwn4kGiPYZpf2PG9hYxLu00JDPalyXtDW/BeOTmtFPnObbWBw89pvbsduSJLqclqgi6Fr9VD86bc9P9iOhWDthSCW1xaOW8uZPbzGAYy2lUSjhwGTkSHqKTDfKTyIZ4r2qlEA/VD1hmq0K6SeuL+d3GGCuqL0jTD9VblfaYVquFTbQ=',
'thunder_username':'+8619370213753',
'thunder_password':'_Hh1860111',
'thunder_captchatoken':'captcha_token=ck0.ASSZcrpDYWgsPZW5mXbsaiP6Wjf3p_7KBQuuoZRvAzB_gpbx2lO5QWdYJLtWBtqZ4EB1dQZFBfwYVkG0P8LNHyw08mm7qfRaCkazGJ93HCSpwcK8cvf9C93T5Dk9L3L7vGc8LO1dPaS1n3Rn5uXVXQ-lgr47Ppui7XxIZvGPyTxO-Fj2KT1WfIsFX92XppWCG5o6UgIqdmsLpGy5GM3eI0fGkUbwHEa0DajLsDFJpr8CrRr2Y8hbvx2lI95LEe9J_vdKYONKZ836rjqiUkvnBVvAxosHwlmfABXpelQb7Oag8V_h1EBSywo5H62zFI2OHRH7CXzV7rQ3rQoXIhpuycmzg1pBCQkhohw3NGxJ7Yg',
'yd_auth':'Basic cGM6MTkzNzAyMTM3NTM6YnB0cXN3SzV8MXxSQ1N8MTcwOTU1MDYyNDU1OXxhUDhCUWZIWF9pblp4RWplX3NZeGdNRC5YYmczQTQ3WGNScTU1MF9lS3VpTVlTMW5WaDBDWllsdHRwZ3lqd19rcTR0SDZJb0VHUW5XVzJ3cHpWMVNyZ2pSZDlub2RzZEhTTXRKdDF5Rlk0UTdYdGJqQ2ZPVS5PalVWZUVjRl91V256T0dvSmxOZm11N0NxVnRqRFBBWVlFTWl4SjUwMmxBT0h2UFZwWmJmTU0t',
'yd_thread_limit':4,
'yd_flags':'4kz|auto',
'yd_danmu':true,
'pikpak_username':'dorabohan@lista.cc',
'pikpak_password':'aa123456',
'pikpak_captchatoken':'captcha_token=ck0.WOH-g8HRRjw9NjGdltxMGsZkRBHz5MGAHLPa7bjUIv_OFWY0cVOrcvhko_j1AFZWU6L9GjkJqW1hrox0mNgAeipykHjpWI8SoNIeqT7odV_iXCpi3x4BQjAGnAhSSboiVw5eoXaJlQ3a1Xj3aOybEY3jUDeODW8bpxinrHaKtVAI3dsdDRlgHRMhMqzk4Evi_D73g3YHiH3Gf-qWBeIqtJqFNFzQkXR3xUmKhlSHqQuvWqicLG_R_jgA7yua30YHPGkSYNQMw3jrBHb7u3Bd7VpwQ5VfNaDtXpS5JPpPyIfihA8hv37feJKIDByvqoY06I8OzPgkcZJBGsyc9JMS16iB5850xocEluyQUQ7C_qU.ClAI7dzG9vgxEhBZVU14NW5JOFpVOEFwOHBtGgUyLjAuMCIMbXlwaWtwYWsuY29tKiBiOTU3ZTM5ZTk0YTk0MjI5YThjODgzYjRiZjVmMGM5ZhKAAWR0EuTfTM_ge4_6KyQqOCf_FlMY-5_JOiIHroOfsLYJuOANXzTyR2_TUxr8HK0Y26lpXQmusmgY2iWWJrVEeVRJgg2x_tegurFEFWAjjS8SppFeVFgTfdzEBxIGQHLQi3VExoZRU7RcHeP2ebG--e4TKLwrP6nNLB6BLkTVqKUA',
'pikpak_flags':'4k|auto',
'pikpak_thread_limit':2,
'pikpak_vip_thread_limit':2,
'pikpak_proxy':'127.0.0.1:10072',
'pikpak_proxy_onlyapi':true,
'pikpak_danmu':true,
'wgcf_key':'',
'wgcf_key2':'',
'wgcf_ipport':'',
'wgcf_xray_url':'./xray.gz',
'wgcf_geoip_url':'./geoip.dat.gz',
'wgcf_json_url':'./wgcf.json',
'wgcf_vless_id':'5008aa6b-004d-477a-9a6b-724df8e2f28a',
'wgcf_vless_optname':'112.3.30.167:80',
'wgcf_vless_worker':'tms.dingtalk.com',
'wgcf_vless_path':'/',
'wgcf_vless_protocol':'vmess',
'wgcf_vless_network':'ws',
'wgcf_vless_tls':false,
'libxl_url':'./libxl_thunder_sdk.so'
}
">$CURRENT_DIR/aa.json

#签到
response=$(curl "https://member.aliyundrive.com/v1/activity/sign_in_list" -X POST -H "User-Agent:$Header" -H "Content-Type:application/json" -H "Authorization:Bearer $access_token" -d '{"grant_type":"refresh_token", "refresh_token":"'$new_token'"}')
success=$(echo $response | cut -f1 -d, | cut -f2 -d:)
if [ $success = "true" ]; then
	echo "阿里签到成功"
fi
signday=$(echo "$response" | grep -o '"day":[0-9]\+' | cut -d':' -f2-)
status=$(echo "$response" | grep -o "\"status\":\"[^\"]*\"" | cut -d':' -f2- | tr -d '"')
isReward=$(echo "$response" | grep -o '"isReward":[^,}]\+' | cut -d':' -f2- | sed '1d')
col=1
for day in $signday; do
	stat=$(echo $status | awk -v col="$col" '{print $col}')
	reward=$(echo $isReward | awk -v col="$col" '{print $col}')
	if [ $stat = "normal" ] && [ "$reward" = "false" ]; then
		echo "正在领取第$day天奖励"
		curl -s -H "User-Agent:$Header" -H "Authorization:Bearer $access_token" -H "Content-Type: application/json" -X POST -d '{"refresh_token":"'$token'", "grant_type": "refresh_token", "signInDay": "'$day'"}' "https://member.aliyundrive.com/v1/activity/sign_in_reward"
	fi
	col=$((col + 1))
done

#删除文件
delete_File() {
	response=$(curl -s -H "User-Agent:$Header" -H "Authorization:Bearer $access_token" -H "Content-Type: application/json" -X POST -d '{"drive_id": "'$drive_id'","parent_file_id": "root"}' "https://api.aliyundrive.com/adrive/v3/file/list")
	if [ -z "$(echo "$response" | grep "items")" ]; then
		echo "获取文件列表失败"
		exit 1
	fi
	file_lines=$(echo "$response" | grep -o "\"file_id\":\"[^\"]*\"" | cut -d':' -f2- | tr -d '"')
	type_lines=$(echo "$response" | grep -o "\"type\":\"[^\"]*\"" | cut -d':' -f2- | tr -d '"')
	col=1
	for file_id in $file_lines; do
		type=$(echo $type_lines | awk -v col="$col" '{print $col}')
		if [ $type = "file" ]; then
			curl -s -H "User-Agent:$Header" -H "Authorization:Bearer $access_token" -H "Content-Type: application/json" -X POST -d '{"requests": [{"body": {"drive_id": "'$drive_id'", "file_id": "'$file_id'"}, "headers": {"Content-Type": "application/json"}, "id": "'$file_id'", "method": "POST", "url": "/file/delete"}], "resource": "file"}' "https://api.aliyundrive.com/v3/batch"
		fi
		col=$((col + 1))
	done
}

INPUT=$1
case $INPUT in
delete_File) delete_File ;;
esac

