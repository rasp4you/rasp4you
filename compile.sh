gcc -Wall -c xtea.c
gcc -Wall -c scan.c
gcc -Wall -c key.c
gcc -Wall -c rasp4you.c
gcc -Wall -c secret.c
gcc -Wall -c release.c
gcc -Wall -c skeleton.c
gcc -Wall -c camera.c
gcc -s -Wall -o rasp4you rasp4you.o secret.o skeleton.o release.o xtea.o scan.o key.o camera.o -lpthread
echo "Rasp4you compiled. To install type ./rasp4you !"
