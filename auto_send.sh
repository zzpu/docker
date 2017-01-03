#!/usr/bin/expect
#set password Dev@Thinputer
set password 123456

set host [lindex $argv 0]

set timeout -1 
set command "killall dockerd"

spawn ssh -o GSSAPIAuthentication=no $host $command
expect {
                 "connecting (yes/no)?"    {send "yes\r";exp_continue}
                 "*password:"    {send "$password\r";exp_continue}
               
       }
sleep 2
spawn bash -c "scp -r -o GSSAPIAuthentication=no /root/docker/bundles/1.13.0-dev/binary-daemon/* root@$host:/usr/bin/"
expect "*password:"
send "$password\r"
expect eof.
spawn bash -c "scp -r -o GSSAPIAuthentication=no /root/docker/bundles/1.13.0-dev/binary-client/* root@$host:/usr/bin/"
expect "*password:"
send "$password\r"
expect eof.
#spawn scp -o GSSAPIAuthentication=no /root/docker/bundles/1.13.0-dev/binary-daemon/docker-containerd root@$host:/usr/bin/
#expect "*password:"
#send "$password\r"
#expect eof.


