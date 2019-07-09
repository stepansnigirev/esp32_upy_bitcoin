test_unix:
	cp -r libs/* micropython/ports/unix/modules;\
	cd micropython/ports/unix;\
	make USER_C_MODULES=../../../usermods;\
	printf "\n*** Test Results ***\n";\
	./micropython -c "import unittest; unittest.main('tests')";

