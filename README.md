# rasp4you
You can connect to Raspberrys located in your home network using a private domain without annoying router configuration. All services, also not http, are available from everywhere. Moreover all ip camera in the private network are easily and automatically available.

For install:

1) copy rasp4you.bin on your Raspberry

2) chmod 755 rasp4you.bin

3) ./rasp4you.bin

After online free your domain reservation you can access to all raspberry services and ip camera on your private network using a domain name. For example if you choose domain "farrel" you have available from everywhere on internet:

ssh root@farrel.rasp4you.com

http://farrel.raspyou.com (your apache)

https://farrel.raspyou.com (your secure apache)

http://farrel.raspyou.com:777 (your apache on 777 port)

also all udp e tcp port services on rasperry are available.

And moverover:

http://router.farrel.rasp4you.com (your router)

http://garage.farrel.rasp4you.com (your ip camera in garage)

http://livingroom.farrel.rasp4you.com:8080 (ip camera on 8080 port)

http://kitchen.farrel.rasp4you.com (another ip camera)

and so your home is "clouded".
