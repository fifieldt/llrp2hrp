# llrp2hrp
A service that talks Low Level Reader Protocol (LLRP) on the frontend and
 Hopeland Reader Protocol (HRP) on the backend

The script implements an LLRP server and addresses the necessary startup and
configuration steps to start sending ROAccessReports that contain EPC data
retrieved from the HRP reader.

This project was primarily designed to feed Webscorer with data from a Hopeland
 CL7026C4 reader so that it could be used for timing trail running races.


Dependencies:
* sllurp
* hrp

## Installing on a Raspberry Pi
This system (CL7026C4 + LLRP2HRP host) is designed so that it can run on a
car battery or UPS for a 12 hour race. A Raspberry Pi 3 is an example of a
low-power computer that would support this context, though a laptop with a
large enough battery of its own could be a viable alternative.

Here is how to install the software and dependencies on a Raspberry Pi.

1. [Download the Raspbian Image](https://www.raspberrypi.org/downloads/raspbian/) and
 [put it on a SD card](https://www.raspberrypi.org/documentation/installation/installing-images/linux.md)
 (16GB is fine)
1. Mount the /boot partition that's now on the SD card and create an empty
 file 'ssh' in the root of the partition
1. Remove the SD card, put it in the Raspberry Pi and boot
1. Work out the IP address of the Pi and ssh to that address
 using the username 'pi'
1. Run raspi-config , disable everything that's not needed, change the
 password, expand the filesystem to fill the card, and reboot.
1. apt-get update; apt-get upgrade; apt-get dist-upgrade
1. apt-get install git python-setuptools python-pip
1. git clone https://github.com/fifieldt/llrp2hrp.git
1. git clone https://github.com/kurenai-ryu/hrp.git
1. git clone https://github.com/fifieldt/sllurp.git (use ransford/sllurp once changes merge)
1. cd sllurp; pip install .
1. The default IP address of the CL7026C4 is 192.168.100.116. Set the ethernet
 interface on the Pi to be on this subnet. eg Edit /etc/dhcpcd.conf with:
 `static ip_address=192.168.100.200/24`
1. now set the llrp2hrp server to start on startup:
1.1 cd /home/pi/llrp2hrp
1.1 cp llrp2hrp.service /lib/systemd/system/
1.1 systemctl daemon-reload
1.1 systemctl enable llrp2hrp.service
1. reboot
