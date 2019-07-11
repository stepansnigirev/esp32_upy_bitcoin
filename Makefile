PORT := /dev/ttyUSB0

test_unix:
	cp -r libs/* micropython/ports/unix/modules;\
	cd micropython/ports/unix;\
	make USER_C_MODULES=../../../usermods;\
	printf "\n*** Test Results ***\n";\
	./micropython -c "import unittest; unittest.main('tests')";

flash:
	cp -r libs/* micropython/ports/esp32/modules;\
	cd micropython/ports/esp32;\
	ESPIDF=~/bin/esp-idf make USER_C_MODULES=../../../usermods;\
	venv/bin/esptool.py --chip esp32 --port $(PORT) --baud 460800 erase_flash;\
	venv/bin/esptool.py --chip esp32 --port $(PORT) --baud 460800 write_flash -z 0x1000 build/firmware.bin


