###TriforceAFL_new

		A tool for simulation, dynamic analysis and fuzzing of IoT firmware.
		Combination of TriforceAFL, firmadyne and DECAF.

####Firmadyne: we use its custom kernel and libnvram to emulate IoT firmware. 
		cd firmadyne 
		See README in firmadyne and do as it says.
		Here, we test DIR-815_FIRMWARE_1.01.ZIP, a router firmware image based on mipsel cpu arch.
		Finally, we replace the run.sh in scratch/(num)/ with our modified one.

####TriforceAFL: AFL fuzzing with full-system emulation
		Run make
  
####DECAF: upgraded to the newest qemu version 2.10.1
		It is included in qemu_mode/qemu dir. 
		If there is something wrong with sleuthkit, plese comment or not comment the following code in configure.
			LIBS="\$(SRC_PATH)/shared/sleuthkit/lib/libtsk.a -lbfd $LIBS

		In our case, run ./configure --target-list=mipsel-softmmu
		Run make

####Usage:
		cd firmadyne
		Run ./scratch/(num)/run.sh 
		In another terminal, run 'telnet 127.0.0.1 4444', into qemu monitor console.
		Load plugin, such as'../qemu_mode/qemu/plugins/callbacktests/callbacktests.so', 'do_callbacktests httpd'
		When firmware system initialization is completed, open a Browser, type a request in url. 		
			like "http://192.168.0.1/hedwig.cgi"
		Finally, fuzz process is started.



