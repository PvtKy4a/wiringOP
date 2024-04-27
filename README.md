## Fork description
This fork adds a CAN interface similar to other wiringOPi interfaces.
The basis was to take the code from the [libsocketcan](https://github.com/lalten/libsocketcan) library.

## Build and install

```
# git clone https://github.com/PvtKy4a/wiringOP.git
# cd wiringOP
# ./build
```
## Uninstall

```
# ./build uninstall
```
## Troubleshooting
If you get this error:
```
# wiringPiSetup: mmap (GPIO) failed: Operation not permitted
```
Or in the “gpio readall” output you see fewer pins than there are on your board, possible solution:
```
# echo "BOARD=orangepi5plus" | sudo tee /etc/orangepi-release
```
Replace "orangepi5plus" with the name of the board you are using.
