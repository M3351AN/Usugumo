call g++ -static -O2 -std=c++23 Target.cc -o Target.exe
call g++ -static -O2 -std=c++23 -DUSING_USUGUMO -I. CallDriver.cc -o CallDriver.exe -lwinmm -lgdi32
call g++ -static -O2 -std=c++23 -I. CallDriver.cc -o Native.exe -lwinmm -lgdi32