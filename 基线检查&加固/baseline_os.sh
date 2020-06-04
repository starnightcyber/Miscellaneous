#!/bin/bash
# ================ Global function for print result ===================
# 绿色字体输出
dash_line="------------------------------------------------------------------"
pass=$(($pass+1))
print_pass(){
    echo -e "\033[32m++> PASS \033[0m"
    echo "++> PASS" >> "$file"
}
# 红色字体输出
fail=$(($fail+1))
print_fail(){
  echo -e "\033[31m--> FAIL \033[0m"
  echo "--> FAIL" >> "$file"
}
# 黄色字体输出
print_manual_check(){
  echo -e "\033[33m##> Manual \033[0m"
  echo "##> Manual" >> "$file"
}
# 蓝色字体输出
print_info(){
  echo -e "\033[34m$1 \033[0m"
}
# 紫色字体输出
print_check_point(){
  echo ""
  echo -e "\033[35m[No."$1"] "$2" \033[0m"
  echo "[$1]"" $2" >> "$file"
}
print_dot_line(){
  echo "$dash_line"
}
print_summary(){
  # 输出显示
  print_info "---------------------------- Summary -----------------------------"
  echo -e "\033[35m全部检测项: $1 \033[0m"
  echo -e "\033[32m通过检测项: $2 \033[0m"
  echo -e "\033[31m失败检测项: $3 \033[0m"
  echo -e "\033[33m手工检测项: $4 \033[0m"
  print_info "检测结果将写入文件 $file中..."
  print_info "$dash_line"
  # 写入文件
  echo "---------------------------- Summary -----------------------------" >> "$file"
  echo "全部检测项: $1" >> "$file"
  echo "通过检测项: $2" >> "$file"
  echo "失败检测项: $3" >> "$file"
  echo "手工检测项: $4" >> "$file"
  echo "$dash_line" >> "$file"
}
# ====================================
begin_msg="-------------------- 正在执行操作系统基线检查 --------------------"
print_info "$begin_msg"
index=0       # 检测项编号
pass=0        # 通过的检测项数
fail=0        # 未通过的检测项数
manual=0      # 需手工复核的检测项数
file="os_check_result.txt"

echo "$begin_msg" > "$file"

check_point="帐号管理-1:检查是否设置除root之外UID为0的用户"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'任何UID为0的帐户都具有系统上的超级用户特权，只有root账号的uid才能为0'"
print_dot_line

result=`/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }'`
print_info "UID为0的用户如下:"
print_info "[ $result ]"

if [ "root" = $result  ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="帐号管理-2:检查是否按用户分配账号 "
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'应按照不同的用户分配不同的账号，避免不同用户间共享账号，避免用户账号和设备间通信使用的账号共享'"
print_dot_line

up_uidmin=`(grep -v ^# /etc/login.defs |grep "^UID_MIN"|awk '($1="UID_MIN"){print $2}')`
up_uidmax=`(grep -v ^# /etc/login.defs |grep "^UID_MAX"|awk '($1="UID_MAX"){print $2}')`
users=`/bin/cat /etc/passwd | /bin/awk -F: '{if( $3>='$up_uidmin' && $3<='$up_uidmax' ) {print $1":"$3}}'`
print_info "系统中存在的用户如下:"
print_info "[ $users ]"

if [ "$users" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="帐号管理-3:检查是否删除与设备运行、维护等工作无关的账号"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'应删除或锁定与设备运行、维护等工作无关的账号'"
print_dot_line
print_info "系统中存在的账号如下:"

account=`/bin/cat /etc/shadow | /usr/bin/sed '/^\s*#/d' | /bin/awk -F: '($2!~/^*/) && ($2!~/^!!/) {print $1}'`
print_info "[ $account ]"

manual=$(($manual+1))
print_manual_check


check_point="帐号管理-4:检查是否设置不同的用户组"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'根据系统要求及用户的业务需求，建立多账户组，将用户账号分配到相应的账户组'"
print_dot_line

groups=`cat /etc/group | awk -F ':' '$3>1000{print $1}'`
print_info "系统中存在的用户自定义用户组 gid >= 1000，如下"
print_info "[ $groups ]"

if [ -n "$groups" ];then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-1:检查是否设置口令生存周期 "
index=$(($index+1))
print_check_point $index "$check_point"

passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^#`

print_info "'PASS_MAX_DAYS 应介于1~90'"
print_dot_line
print_info "$passmax"

if [ -n "$passmax" ]; then
  days=`echo $passmax | awk '{print $2}'`
  if [ "$days" -gt 90 ]; then
      fail=$(($fail+1))
      print_fail
  else
      pass=$(($pass+1))
      print_pass
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-2:检查是否设置口令更改最小间隔天数 "
index=$(($index+1))
print_check_point $index "$check_point"

passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^#`

print_info "'PASS_MIN_DAYS 应大于等于 7'"
print_dot_line
print_info "$passmin"

if [ -n "$passmin" ]; then
  days=`echo $passmin | awk '{print $2}'`
  if [ "$days" -lt 7 ]; then
      fail=$(($fail+1))
      print_fail
  else
      pass=$(($pass+1))
      print_pass
  fi
else
  fail=$(($fail+1))
  print_fail
fi

check_point="口令策略-3:检查是否设置口令过期前警告天数  "
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'口令过期前告警天数PASS_WARN_AGE应设置为 7'"
print_dot_line

pass_age=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# `
print_info "$pass_age"

if [ -n "$pass_age" ]; then
  days=`echo $pass_age | awk '{print $2}'`
  if [ "$days" -eq 7 ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-4:检查设备密码复杂度策略"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'密码长度>=8，且至少包含一个大写字母、小写字母、数字、特殊字符'"
print_dot_line
print_info "系统目前的密码复杂度策略，如下:"
info=`cat /etc/pam.d/system-auth | grep password | grep requisite`
print_info "$info"

line=`cat /etc/pam.d/system-auth | grep password | grep pam_cracklib.so | grep -v ^#`
if [ -n "$line" ]; then
  check_min=`echo $line | grep minlen`
  check_dcredit=`echo $line | grep dcredit`
  check_ucredit=`echo $line | grep ucredit`
  check_ocredit=`echo $line | grep ocredit`
  check_lcredit=`echo $line | grep lcredit`

  if [ -n "$check_min"  ] && [ -n "$check_dcredit"  ] && [ -n "$check_ucredit"  ] && [ -n "$check_ocredit"  ] && [ -n "$check_lcredit"  ]; then
    minlen=`echo $line | awk -F 'minlen=' '{print $2}' | awk -F ' ' '{print $1}'`
    dcredit=`echo $line | awk -F 'dcredit=' '{print $2}' | awk -F ' ' '{print $1}'`
    ucredit=`echo $line | awk -F 'ucredit=' '{print $2}' | awk -F ' ' '{print $1}'`
    ocredit=`echo $line | awk -F 'ocredit=' '{print $2}' | awk -F ' ' '{print $1}'`
    lcredit=`echo $line | awk -F 'lcredit=' '{print $2}' | awk -F ' ' '{print $1}'`

    if [ "$minlen" -ge 8 ] && [ ${dcredit#-} -ge 1 ] && [ ${ucredit#-} -ge 1 ] && [ ${ucredit#-} -ge 1 ] && \
     [ ${ocredit#-} -ge 1 ] && [ ${lcredit#-} -ge 1 ]; then
      pass=$(($pass+1))
      print_pass
    else
      fail=$(($fail+1))
      print_fail
    fi
  else
    fail=$(($fail+1))
    print_fail
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-5:检查是否存在空口令账号"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'不允许存在空口令的账号'"
print_dot_line

tmp=`/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print "user " $1 " does not have a password "}'`
print_info '空口令账号:'"[ $tmp ]"

if [ -z "$tmp" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-6:检查密码重复使用次数限制"
index=$(($index+1))
print_check_point $index "$check_point"

line=`cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^#`
print_info "'口令重复使用限制次数 remember >=5'"
print_dot_line
print_info "[ $line ]"

if [ -n "$line" ]; then
  times=`echo $line|awk -F "remember=" '{print $2}'`
  if [ $times -ge 5 ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="口令策略-7:检查账户认证失败次数限制"
index=$(($index+1))
print_check_point $index "$check_point"

print_dot_line
print_info "登录失败限制可以使用pam_tally或pam.d，请手工检测/etc/pam.d/system-auth"

manual=$(($manual+1))
print_manual_check


check_point="认证授权-1:检查用户目录缺省访问权限设置 "
index=$(($index+1))
print_check_point $index "$check_point"

tmp=`umask`
print_info "'文件目录缺省访问权限应是 027'"
print_dot_line
print_info "实际检测值为:"
print_info "[ $tmp ]"

tt=`echo $tmp | grep 027`

if [ -n "$tt" ];then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="认证授权-2:检查是否设置SSH登录前警告Banner"
index=$(($index+1))
print_check_point $index "$check_point"

banner1=`cat /etc/ssh/sshd_config | grep Banner`
print_info "'检查SSH配置文件:/etc/ssh/sshd_config，未启用banner或合理设置banner的内容'"
print_dot_line
print_info "$banner1"

# 如果banner为空或者为 None，则符合要求
if [ -z "$banner1" ]; then
  print_info "不存在Banner配置项"
  fail=$(($fail+1))
  print_fail
else
  banner2=`cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}' | grep -v "none"`
  if [ -z "$banner2" ]; then
    print_info "未配置Banner路径文件"
    fail=$(($fail+1))
    print_fail
  else
    manual=$(($manual+1))
    path=`cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}'`
    print_info "请手工检查文件 $path 是否符合要求"
    print_manual_check
  fi
fi


check_point="日志审计-1:检查是否对登录进行日志记录"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'设备应配置日志功能，对用户登录进行记录，记录内容包括用户登录使用的账号，登录是否成功，登录时间，以及远程登录时，用户使用的IP地址'"
tmp=`cat /etc/rsyslog.conf | grep /var/log/secure | egrep 'authpriv'.\('info|\*'\) | grep -v ^#`
print_dot_line
print_info "/etc/rsyslog.conf 文件中 authpriv 的配置如下所示:"
print_info "$tmp"

if [ -n "$tmp" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="日志审计-2:检查是否启用cron行为日志功能"
index=$(($index+1))
print_check_point $index "$check_point"

print_dot_line
tmp=`cat /etc/rsyslog.conf | grep /var/log/cron | egrep 'cron.\*' | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 cron 的配置如下所示:"
print_info "$tmp"

if [ -n "$tmp" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="日志审计-3:检查是否配置远程日志功能"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'在远程主机上存储日志数据保护日志完整性免受本地攻击'"
print_dot_line
msg="请检查/etc/rsyslog.conf文件，查看是否配置日志服务器"
print_info "$msg"

manual=$(($manual+1))
print_manual_check


check_point="日志审计-4:检查是否配置su命令使用情况记录"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'启用syslog系统日志审计功能'"
print_dot_line
tmp=`cat /etc/rsyslog.conf | grep /var/log/secure | egrep 'authpriv'.\('info|\*'\) | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 authpriv 的配置如下所示:"
print_info "$tmp"

if [ -n "$tmp" ]; then
  pass=$(($pass+1))
print_pass
else
  fail=$(($fail+1))
print_fail
fi


check_point="日志审计-5:检查日志文件权限设置"
index=$(($index+1))
print_check_point $index "$check_point"

messages=`stat -c %a /var/log/messages`
dmesg=`stat -c %a /var/log/dmesg`
maillog=`stat -c %a /var/log/maillog`
secure=`stat -c %a /var/log/secure`
wtmp=`stat -c %a /var/log/wtmp`
cron=`stat -c %a /var/log/cron`

print_info "'设备应配置权限，控制对日志文件读取、修改和删除等操作'"
print_info "推荐的文件权限:(不大于左侧值)"
print_info "600 /var/log/messages"
print_info "600 /var/log/secure、"
print_info "600 /var/log/maillog、"
print_info "600 /var/log/cron"
print_info "644 /var/log/dmesg"
print_info "664 /var/log/wtmp"
print_dot_line
print_info "目前的文件权限如下:"
print_info $messages' /var/log/messages'
print_info $dmesg' /var/log/dmesg  '
print_info $maillog' /var/log/maillog  '
print_info $secure' /var/log/secure  '
print_info $wtmp' /var/log/wtmp  '
print_info $cron' /var/log/cron  '

if [ "$messages" -le 600 ] && [ "$secure" -le 600 ] && [ "$maillog" -le 600 ] && [ "$cron" -le 600 ] && [ "$dmesg" -le 644 ] && [ "$wtmp" -le 644 ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="日志审计-6:检查安全事件日志配置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'设备应配置日志功能，记录对与设备相关的安全事件'"
print_dot_line
tmp=`cat /etc/rsyslog.conf | grep /var/log/messages | egrep '\*.info;mail.none;authpriv.none;cron.none' | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 /var/log/messages 的配置如下所示:"
print_info "$tmp"

if [ -n "$tmp" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="文件权限-1:检查FTP用户上传的文件所具有的权限"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'FTP服务未运行，或ftp用户和匿名用户上传文件的权限为022'"
print_dot_line

tmp=`netstat -lntp | grep ftp`
print_info "$tmp"
if [ -z "$tmp" ]; then
  print_info "No FTP Service"
  pass=$(($pass+1))
  print_pass
else
  local_umask=`cat /etc/vsftpd/vsftpd.conf | grep local_umask | grep 022 | grep -v ^#`
  anon_umask=`cat /etc/vsftpd/vsftpd.conf | grep anon_umask | grep 022 | grep -v ^#`
  if [ -n "$local_umask" ] && [ -n "$anon_umask" ]; then
    pass=$(($pass+1))
    print_pass
  else
    print_info 'local_umask:'"[ $local_umask ]"
    print_info 'anon_umask:'"[ $anon_umask ]"
    fail=$(($fail+1))
    print_fail
  fi
fi


check_point="文件权限-2:检查重要目录或文件权限设置"
index=$(($index+1))
print_check_point $index "$check_point"

passwd=`stat -c %a /etc/passwd`
shadow=`stat -c %a /etc/shadow`
group=`stat -c %a /etc/group`

print_info "'在设备权限配置能力内，根据用户的业务需要，配置其所需的最小权限'"
print_info "建议文件权限:(不大于左侧值)"
print_info "644 /etc/passwd"
print_info "400 /etc/shadow"
print_info "644 /etc/group"
print_dot_line
print_info "实际检测值为:"
print_info "$passwd"" /etc/passwd"
print_info "$shadow"" /etc/shadow"
print_info "$group"" /etc/group"

if [ "$passwd" -le 644 ] && [ "$shadow" -le 400 ] && [ "$group" -le 644 ]; then
  pass=$(($pass+1))
print_pass
else
  fail=$(($fail+1))
print_fail
fi


check_point="网络通信-1:检查是否禁止root用户远程登录"
index=$(($index+1))
print_check_point $index "$check_point"

Protocol=`cat /etc/ssh/sshd_config | grep -i Protocol | egrep -v ^\# | awk '{print $2}'`
PermitRootLogin=`cat /etc/ssh/sshd_config | grep -i PermitRootLogin | egrep -v ^\# | awk '{print $2}'`
print_info "'PermitRootLogin 为no 且 Protocol 为2'"
print_dot_line
print_info "/etc/ssh/sshd_config 两项配置如下:"
print_info 'PermitRootLogin ==> '"[ $PermitRootLogin ]"
print_info 'Protocol ==> '"[ $Protocol ]"

if [ "$PermitRootLogin" = "no" ] && [ "$Protocol" -eq 2 ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi

check_point="网络通信-2:检查使用IP协议远程维护的设备是否配置SSH协议，禁用Telnet协议"
index=$(($index+1))
print_check_point $index "$check_point"
print_dot_line

telnet=`netstat -lntp |grep telnet`
ssh=`netstat -lntp |grep ssh`

print_info "==> telnet"
print_info "$telnet"
print_info "==> ssh"
print_info "$ssh"

if [ -z "$telnet" ] && [ -n "$ssh" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="网络通信-3:检查是否修改SNMP默认团体字"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'如果没有必要，需要停止SNMP服务，如果确实需要使用SNMP服务，需要修改SNMP默认团体字'"
print_dot_line
snmp=`ps -ef|grep "snmpd"|grep -v "grep"`

if [ -z "$snmp" ]; then
  print_info "SNMP Server is not running..."
  pass=$(($pass+1))
  print_pass
else
  string=`cat /etc/snmp/snmpd.conf | grep com2sec  | grep public | grep -v ^# `
  if [ -n "$string" ]; then
    fail=$(($fail+1))
    print_fail
  else
    pass=$(($pass+1))
    print_pass
  fi
fi


check_point="网络通信-4:检查是否禁止root用户登录FTP"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'FTP服务未运行 或 root被禁用'"
print_dot_line

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
  print_info "No FTP Service"
  pass=$(($pass+1))
  print_pass
else
  print_info "1.FTP服务正在运行..."
  print_info "2.检查 /etc/vsftpd/ftpusers 配置文件中是否有root，以下是文件内容"
  print_info "`cat /etc/vsftpd/ftpusers`"
  root=`cat /etc/vsftpd/ftpusers | grep root | grep -v ^#`
  if [ -n "$root" ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
fi


check_point="网络通信-5:检查是否使用PAM认证模块禁止wheel组之外的用户su为root"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'使用PAM禁止任何人su为root'"
print_info "检查/etc/pam.d/su文件中，是否存在如下配置:"
print_info "auth  sufficient pam_rootok.so"
print_info "auth  required pam_wheel.so group=wheel"
print_dot_line

pam_rootok=`cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#`
pam_wheel=`cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#`

print_info "实际配置如下:"
print_info "$pam_rootok"
print_info "$pam_wheel"

if [ -n "$pam_rootok" ] && [ -n "$pam_wheel" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-1:检查是否禁止匿名用户登录FTP"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'FTP服务未启用或者限制了匿名账号登录ftp服务器则合规'"
print_dot_line

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
  print_info "No FTP Service"
  pass=$(($pass+1))
  print_pass
else
  tmp=`cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable=NO" | grep -v ^#`
  if [ -z "$tmp" ]; then
    tmp=`cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable" | grep -v ^#`
    print_info "$tmp"
    fail=$(($fail+1))
    print_fail
  else
    pass=$(($pass+1))
    print_pass
  fi
fi


check_point="其他配置-2:检查是否删除了潜在危险文件"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'系统不应该存在.rhost、.netrc、hosts.equiv这三个文件则合规'"
print_dot_line

rhost=`locate .rhost | egrep 'rhost$'`
equiv=`locate .netrc | egrep 'netrc$'`
equiv=`locate .equiv | egrep 'hosts.equiv$'`

print_info "rhost ==> "" [ $rhost ]"
print_info "netrc ==> "" [ $netrc ]"
print_info "equiv ==> "" [ $equiv ]"

if [ -z "$rhost" ] && [ -z "$netrc" ] && [ -z "$equiv" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-3:检查是否设置命令行界面超时退出"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'命令行界面超时自动登出时间TMOUT应不大于300s'"
print_dot_line
TMOUT=`cat /etc/profile |grep -i TMOUT | grep -v ^#`

if [ -z "$TMOUT" ]; then
  print_info "没有设置超时时间TMOUT"
  fail=$(($fail+1))
  print_fail
else
  TMOUT=`cat /etc/profile |grep -i TMOUT | egrep -v ^\# | awk -F "=" '{print $2}'`
  if [ "$TMOUT" -gt 300 ]; then
    print_info "TMOUT值过大:""$TMOUT"
    fail=$(($fail+1))
    print_fail
  else
    print_info "TMOUT:""$TMOUT"
    pass=$(($pass+1))
    print_pass
  fi
fi


check_point="其他配置-4:检查系统是否禁用Ctrl+Alt+Delete组合键"
index=$(($index+1))
print_check_point $index "$check_point"

tmp=`cat /usr/lib/systemd/system/ctrl-alt-del.target | grep "Alias=ctrl-alt-del.target" | grep -v ^#`
print_info "'应禁用Ctrl+Alt+Delete组合键重启系统'"
print_dot_line
print_info "Ctrl+Alt+Delete的配置如下:"
print_info $tmp

if [ -n "$tmp" ]; then
  fail=$(($fail+1))
  print_fail
else
  pass=$(($pass+1))
  print_pass
fi


check_point="其他配置-5:检查root用户的path环境变量"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'PATH环境变量中不存在.或者..的路径(此处以不存在'..'为检查条件，因为'.'可能会存在于软件版本号中)'"
print_dot_line
print_info "PATH环境变量如下:"

tmp=`echo $PATH | egrep '\.\.'`
print_info "$PATH"
if [ -z "$tmp" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-6:检查历史命令设置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'HISTFILESIZE和HISTSIZE的值应小于等于5'"
print_dot_line
print_info "实际检测值为:"

HISTSIZE=`cat /etc/profile | grep ^HISTSIZE | egrep -v ^\#`
HISTFILESIZE=`cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\#`

if [ -n "$HISTSIZE" ] && [ -n "$HISTFILESIZE" ]; then
  HISTSIZE=`cat /etc/profile | grep HISTSIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  HISTFILESIZE=`cat /etc/profile | grep HISTFILESIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  print_info "HISTSIZE => "" [ $HISTSIZE ]"
  print_info "HISTFILESIZE => "" [ $HISTFILESIZE ]"

  if [ "$HISTSIZE" -lt 5 ] && [ "$HISTFILESIZE" -lt 5 ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-7:检查是否设置SSH成功登录后Banner"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'用户通过网络或者本地成功登录系统后，显示一些警告信息'"
print_dot_line
tmp=`systemctl status sshd | grep running`
if [ -z "$tmp" ]; then
  print_info "==>SSHD is not running..."
  pass=$(($pass+1))
  print_pass
else
  temp=`cat /etc/motd`
  if [ -n "$temp" ]; then
    print_info "请手工检查/etc/motd文件中的内容是否符合要求"
    print_info "$temp"
    manual=$(($manual+1))
    print_manual_check
  else
    print_info "/etc/motd文件中内容为空，不提示登录信息"
    fail=$(($fail+1))
    print_fail
  fi
fi


check_point="其他配置-8:检查是否限制FTP用户登录后能访问的目录"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'FTP服务器应该限制FTP可以使用的目录范围'"
print_dot_line

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
  print_info "No FTP Service Running"
  pass=$(($pass+1))
  print_pass
else
  chroot_local_user=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_local_user=NO`
  chroot_list_enable=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_enable=YES`
  chroot_list_file=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_file=/etc/vsftpd/chroot_list`

  if [ -n "$chroot_local_user" ] && [ -n "$chroot_list_enable" ] && [ -n "$chroot_list_file" ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
fi


check_point="其他配置-9:检查是否关闭数据包转发功能"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'对于不做路由功能的系统，应该关闭数据包转发功能'"
print_dot_line
ip_forward=`sysctl -n net.ipv4.ip_forward`
print_info '实际值 ==> ip_forward:'$ip_forward

if [ 0 -eq "$ip_forward" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-10:检查别名文件/etc/aliase"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'检查是否配合配置了ls和rm命令别名'"
print_dot_line

aol=`cat  ~/.bashrc | grep "^alias ls='ls -aol'"`
rmi=`cat  ~/.bashrc | grep "^alias rm='rm -i"`

print_info "aol ==> "" [ $aol ]"
print_info "rmi ==> "" [ $rmi ]"

if [ -n "$aol" ] && [ -n "$rmi" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-11:检查是否使用NTP（网络时间协议）保持时间同步"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'如果网络中存在信任的NTP服务器，应该配置系统使用NTP服务保持时间同步'"
print_dot_line
print_info "NTP服务运行状态信息："
ntpd=`ps -ef|egrep "ntp|ntpd"|grep -v grep | grep "/usr/sbin/ntpd"`
print_info "$ntpd"

if [ -n "$ntpd" ]; then
  server=`cat /etc/ntp.conf | grep ^server`
  print_info "==> servers <=="
  print_info "$server"
  if [ -n "$server" ]; then
    pass=$(($pass+1))
    print_pass
  else
    fail=$(($fail+1))
    print_fail
  fi
else
  print_info "==> NTP Service is not running..."
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-12:检查是否限制远程登录IP范围"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'设备应支持对允许登录到该设备的IP地址范围进行设定'"
print_dot_line
print_info "请手工查看/etc/hosts.allow和/etc/hosts.deny两个文件"
manual=$(($manual+1))
print_manual_check


check_point="其他配置-13:检查NFS（网络文件系统）服务配置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'如果没有必要，需要停止NFS服务；如果需要NFS服务，需要限制能够访问NFS服务的IP范围'"
print_dot_line

tmp=`netstat -lntp | grep nfs`
if [ -z "$tmp" ]; then
  print_info "NFS 服务未启用..."
  pass=$(($pass+1))
  print_pass
else
  allow=`cat /etc/hosts.allow | grep -v ^#`
  deny=`cat /etc/hosts.deny | grep -v ^#`
  if [ -n "$allow" ] && [ -n "$deny" ]; then
    print_info "hosts.allow 和 hosts.deny皆已配置"
    pass=$(($pass+1))
    print_pass
  else
    print_info "未配置hosts.allow 或 hosts.deny"
    fail=$(($fail+1))
    print_fail
  fi
fi


check_point="其他配置-14:检查是否配置定时自动屏幕锁定"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'对于具备图形界面（含WEB界面）的设备，应配置定时自动屏幕锁定(没有界面可忽略此项)'"
print_dot_line

idle_activation_enabled=`gconftool-2 -g /apps/gnome-screensaver/idle_activation_enabled`
lock_enabled=`gconftool-2 -g /apps/gnome-screensaver/lock_enabled`
mode=`gconftool-2 -g /apps/gnome-screensaver/mode`
idle_delay=`gconftool-2 -g /apps/gnome-screensaver/idle_delay`

print_info "idle_activation_enabled ==> ""$idle_activation_enabled"
print_info "lock_enabled ==> ""$lock_enabled"
print_info "mode ==> ""$mode"
print_info "idle_delay ==> ""$idle_delay"

if  [ "$idle_activation_enabled" == "true" ] && [ "$lock_enabled" == "true" ] \
  && [ "$mode" == "blank-only" ] && [ "$idle_delay" -le 15 ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-15:检查是否安装chkrootkit进行系统监测"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'安装入侵检测攻击检查Linux系统是否遭受攻击'"
print_dot_line

chkrootkit=`rpm -qa|grep -i "chkrootkit"`
print_info "chkrootkit ==> "" [ $chkrootkit ]"
if [ -n "$chkrootkit" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-16:检查是否安装OS补丁"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'手工检查当前系统版本是否安装最新补丁'"
print_dot_line

os=`uname -a`
print_info "==> please manual check os version ..."
print_info "$os"
echo "$os" >> "$file"
manual=$(($manual+1))
print_manual_check


check_point="其他配置-17:检查FTP banner设置"
index=$(($index+1))
print_check_point $index "$check_point"

print_dot_line
tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$banner" ]; then
  print_info "FTP Service is not Running..."
  pass=$(($pass+1))
  print_pass
else
  print_info "请手工检查/etc/vsftpd/vsftpd.conf文件中的banner是否符合要求"
  manual=$(($manual+1))
  print_manual_check
fi


check_point="其他配置-18:检查Telnet banner设置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'FTP登录时需要显示警告信息，隐藏操作系统和FTP服务器相关信息'"
print_dot_line

tmp=`systemctl status telnet.socket  | grep active`
if [ -z "$tmp" ]; then
  print_info "==>Telnet service is not installed or not running..."
  pass=$(($pass+1))
  print_pass
else
  print_info "Please check /etc/issue、/etc/issue.net whether contains banner information"
  manual=$(($manual+1))
  print_manual_check
fi


check_point="其他配置-19:检查系统内核参数配置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'调整内核安全参数，增强系统安全性，tcp_syncookies的值应设为1'"
print_dot_line

tcp_syncookies=`cat /proc/sys/net/ipv4/tcp_syncookies`
print_info "tcp_syncookies ==> ""$tcp_syncookies"

if [ "$tcp_syncookies" -eq 1 ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-20:检查系统openssh安全配置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'建议系统放弃旧的明文登录协议，使用SSH防止会话劫持和嗅探网络上的敏感数据'"
print_dot_line

X11Forwarding=`cat /etc/ssh/sshd_config  | grep X11Forwarding | egrep -v ^\# | awk '{print $2}'`
MaxAuthTries=`cat /etc/ssh/sshd_config  | grep MaxAuthTries | egrep -v ^\# | awk '{print $2}'`
IgnoreRhosts=`cat /etc/ssh/sshd_config  | grep IgnoreRhosts  | egrep -v ^\# | awk '{print $2}'`
HostbasedAuthentication=`cat /etc/ssh/sshd_config  | grep HostbasedAuthentication | egrep -v ^\# | awk '{print $2}'`
PermitEmptyPasswords=`cat /etc/ssh/sshd_config  | grep PermitEmptyPasswords | egrep -v ^\# | awk '{print $2}'`

print_info "X11Forwarding => ""$X11Forwarding"
print_info "MaxAuthTries => ""$MaxAuthTries"
print_info "IgnoreRhosts => ""$IgnoreRhosts"
print_info "HostbasedAuthentication => ""$HostbasedAuthentication"
print_info "PermitEmptyPasswords => ""$PermitEmptyPasswords"

if [ "$X11Forwarding" = "no" ] && [ "$MaxAuthTries" -le 4 ] && [ "$IgnoreRhosts" = "yes" ] && \
  [ "$HostbasedAuthentication" = "no" ] && [ "$PermitEmptyPasswords" = "no" ]; then
  pass=$(($pass+1))
  print_pass
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-21:检查系统coredump设置"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'core dump中可能包括系统信息，易被入侵者利用，建议关闭'"
print_info "设置* soft  core、* hard core为0，且注释掉ulimit -S -c 0 > /dev/null 2>&1"
print_dot_line

soft=`cat /etc/security/limits.conf | grep soft | grep core | grep 0 | grep ^*`
hard=`cat /etc/security/limits.conf | grep hard | grep core | grep 0 | grep ^*`

if [ -n "$soft" ] && [ -n "$hard" ]; then
  tmp=`cat /etc/profile | grep "ulimit -S -c 0 > /dev/null 2>&1" | grep -v ^#`
  if [ -n $tmp ]; then
    fail=$(($fail+1))
    print_fail
  else
    pass=$(($pass+1))
    print_pass
  fi
else
  fail=$(($fail+1))
  print_fail
fi


check_point="其他配置-22:检查是否关闭不必要的服务和端口"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'结合实际业务需要人工判断是否存在不必要的未关闭的端口和服务，请通过以下命令，手工检查'"
print_dot_line
print_info "# chkconfig --list"

manual=$(($manual+1))
print_manual_check


check_point="其他配置-23:检查磁盘空间占用率"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'检查磁盘空间占用率，建议不超过80%'"
print_dot_line

print_info "`df -h`"
space=$(df -h | awk -F "[ %]+" 'NR!=1''{print $5}')
flag=0
for i in $space
do
  if [ $i -ge 80 ];then
    flag=1
    print_info "请使用命令手工检查磁盘空间占用率情况"
  fi
done

if [ "$flag" -eq 1 ];then
  manual=$(($manual+1))
  print_manual_check
else
  pass=$(($pass+1))
  print_pass
fi

print_summary $index $pass $fail $manual
